using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Qeli.Shared;

namespace QeliWin;

/// <summary>Minimal modal text-input dialog built in code (no separate XAML).</summary>
public static class InputDialog
{
    public static string? Show(Window owner, string title, string prompt, string initial, bool multiline = false)
    {
        var bg = (Brush)Application.Current.FindResource("Bg");
        var panel = (Brush)Application.Current.FindResource("Panel");
        var fg = (Brush)Application.Current.FindResource("Fg");

        var win = new Window
        {
            Title = title, Width = 560, Height = multiline ? 440 : 210,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Owner = owner,
            Background = bg, ResizeMode = ResizeMode.CanResize,
            FontFamily = (FontFamily)Application.Current.FindResource("UiFont"),
        };

        var grid = new Grid { Margin = new Thickness(16) };
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var label = new TextBlock { Text = prompt, Foreground = fg, Margin = new Thickness(0, 0, 0, 8) };
        Grid.SetRow(label, 0);

        var box = new TextBox
        {
            Text = initial, Foreground = fg, Background = panel, BorderThickness = new Thickness(0),
            Padding = new Thickness(10), FontFamily = new FontFamily("Consolas"), FontSize = 13,
            AcceptsReturn = multiline, TextWrapping = multiline ? TextWrapping.Wrap : TextWrapping.NoWrap,
            VerticalScrollBarVisibility = multiline ? ScrollBarVisibility.Auto : ScrollBarVisibility.Disabled,
            VerticalContentAlignment = multiline ? VerticalAlignment.Top : VerticalAlignment.Center,
        };
        Grid.SetRow(box, 1);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 12, 0, 0),
        };
        string? result = null;
        var cancel = new Button
        {
            Content = Loc.T("Cancel"), MinWidth = 104, Margin = new Thickness(0, 0, 10, 0),
        };
        var ok = new Button
        {
            Content = "OK", MinWidth = 120,
            Style = (Style)Application.Current.FindResource("AccentButton"),
        };
        ok.Click += (_, _) => { result = box.Text; win.DialogResult = true; };
        cancel.Click += (_, _) => { win.DialogResult = false; };
        buttons.Children.Add(cancel);
        buttons.Children.Add(ok);
        Grid.SetRow(buttons, 2);

        grid.Children.Add(label);
        grid.Children.Add(box);
        grid.Children.Add(buttons);
        win.Content = grid;
        box.Focus();
        box.SelectAll();

        return win.ShowDialog() == true ? result : null;
    }
}
