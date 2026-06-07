using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace QeliMac;

/// <summary>
/// Small themed modal dialogs (info / confirm) — Avalonia has no built-in MessageBox,
/// so this stands in for the WPF MessageBox calls qeli-win used. All async (Avalonia's
/// ShowDialog is awaitable).
/// </summary>
public static class Dialogs
{
    public static Task InfoAsync(Window owner, string text, string title) => ShowAsync(owner, text, title, confirm: false);

    public static Task<bool> ConfirmAsync(Window owner, string text, string title) => ShowAsync(owner, text, title, confirm: true);

    private static async Task<bool> ShowAsync(Window owner, string text, string title, bool confirm)
    {
        IBrush B(string k) => owner.FindResource(k) as IBrush ?? Brushes.Gray;

        bool result = false;
        var win = new Window
        {
            Title = title, Width = 460, SizeToContent = SizeToContent.Height, CanResize = false,
            Background = B("Bg"), WindowStartupLocation = WindowStartupLocation.CenterOwner,
            ShowInTaskbar = false, Icon = owner.Icon,
        };

        var msg = new TextBlock
        {
            Text = text, Foreground = B("Fg"), TextWrapping = TextWrapping.Wrap, Margin = new(0, 0, 0, 18),
        };

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Spacing = 10 };
        if (confirm)
        {
            var no = new Button { Content = Loc.T("No"), MinWidth = 104 };
            no.Click += (_, _) => win.Close();
            var yes = new Button { Content = Loc.T("Yes"), MinWidth = 120 };
            yes.Classes.Add("accent");
            yes.Click += (_, _) => { result = true; win.Close(); };
            buttons.Children.Add(no);
            buttons.Children.Add(yes);
        }
        else
        {
            var ok = new Button { Content = "OK", MinWidth = 120 };
            ok.Classes.Add("accent");
            ok.Click += (_, _) => win.Close();
            buttons.Children.Add(ok);
        }

        win.Content = new StackPanel { Margin = new(22), Children = { msg, buttons } };
        await win.ShowDialog(owner);
        return result;
    }
}
