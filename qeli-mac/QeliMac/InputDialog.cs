using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Qeli.Shared;

namespace QeliMac;

/// <summary>Minimal modal text-input dialog built in code (no separate XAML). Async port
/// of qeli-win's WPF InputDialog.</summary>
public static class InputDialog
{
    public static async Task<string?> ShowAsync(Window owner, string title, string prompt, string initial, bool multiline = false)
    {
        IBrush B(string k) => owner.FindResource(k) as IBrush ?? Brushes.Gray;

        var win = new Window
        {
            Title = title, Width = 560, Height = multiline ? 440 : 210,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = B("Bg"), CanResize = true, ShowInTaskbar = false, Icon = owner.Icon,
        };

        var grid = new Grid { Margin = new(16), RowDefinitions = new RowDefinitions("Auto,*,Auto") };

        var label = new TextBlock { Text = prompt, Foreground = B("Fg"), Margin = new(0, 0, 0, 8) };
        Grid.SetRow(label, 0);

        var box = new TextBox
        {
            Text = initial, FontFamily = new FontFamily("Menlo, Monaco, Consolas"), FontSize = 13,
            AcceptsReturn = multiline,
            TextWrapping = multiline ? TextWrapping.Wrap : TextWrapping.NoWrap,
            VerticalContentAlignment = multiline ? VerticalAlignment.Top : VerticalAlignment.Center,
        };
        Grid.SetRow(box, 1);

        string? result = null;
        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 10, Margin = new(0, 12, 0, 0),
        };
        var cancel = new Button { Content = Loc.T("Cancel"), MinWidth = 104 };
        cancel.Click += (_, _) => win.Close();
        var ok = new Button { Content = "OK", MinWidth = 120 };
        ok.Classes.Add("accent");
        ok.Click += (_, _) => { result = box.Text; win.Close(); };
        buttons.Children.Add(cancel);
        buttons.Children.Add(ok);
        Grid.SetRow(buttons, 2);

        grid.Children.Add(label);
        grid.Children.Add(box);
        grid.Children.Add(buttons);
        win.Content = grid;

        win.Opened += (_, _) => { box.Focus(); box.SelectAll(); };
        await win.ShowDialog(owner);
        return result;
    }
}
