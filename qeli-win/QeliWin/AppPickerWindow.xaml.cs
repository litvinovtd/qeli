using System.Windows;
using System.Windows.Controls;
using Qeli.Shared;
using QeliWin.Vpn;

namespace QeliWin;

/// <summary>Pick .exe paths for per-app split tunnelling. Lists currently running
/// non-system processes; returns the selected full paths (or null on cancel).</summary>
public sealed class AppPickerWindow : Window
{
    private readonly HashSet<string> _selected;
    private ListBox _list = null!;
    private TextBox _filter = null!;
    private List<(string path, string name)> _all = new();
    private List<string>? _result;

    public AppPickerWindow(Window owner, IEnumerable<string> selected)
    {
        Owner = owner;
        Icon = owner.Icon;
        Title = Loc.T("AppsPickerTitle");
        Width = 560;
        Height = 480;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResizeWithGrip;
        Background = (System.Windows.Media.Brush)FindResource("Bg");
        FontFamily = (System.Windows.Media.FontFamily)FindResource("UiFont");

        _selected = new HashSet<string>(
            selected.Select(ProcessAppMap.NormalizePath).Where(p => p.Length > 0),
            StringComparer.OrdinalIgnoreCase);

        var root = new DockPanel { Margin = new Thickness(16) };

        var bottom = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 12, 0, 0),
        };
        DockPanel.SetDock(bottom, Dock.Bottom);
        var cancel = new Button { Content = Loc.T("Cancel"), MinWidth = 104, Margin = new Thickness(0, 0, 10, 0) };
        cancel.Click += (_, _) => { DialogResult = false; };
        var ok = new Button { Content = Loc.T("Save"), MinWidth = 130, Style = (Style)FindResource("AccentButton") };
        ok.Click += OnOk;
        bottom.Children.Add(cancel);
        bottom.Children.Add(ok);
        root.Children.Add(bottom);

        var top = new StackPanel { Margin = new Thickness(0, 0, 0, 10) };
        DockPanel.SetDock(top, Dock.Top);
        top.Children.Add(new TextBlock
        {
            Text = Loc.T("AppsPickerHint"),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 8),
            Opacity = 0.85,
        });
        _filter = new TextBox();
        _filter.TextChanged += (_, _) => RebuildList();
        top.Children.Add(_filter);
        var browseRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
        var browse = new Button { Content = Loc.T("AppsBrowse"), MinWidth = 140 };
        browse.Click += OnBrowse;
        browseRow.Children.Add(browse);
        top.Children.Add(browseRow);
        root.Children.Add(top);

        _list = new ListBox { BorderThickness = new Thickness(1) };
        root.Children.Add(_list);

        Content = root;

        Loaded += (_, _) =>
        {
            _all = ProcessAppMap.ListCandidateApps();
            // Keep manually-selected paths that are not currently running.
            foreach (var path in _selected)
            {
                if (_all.Any(a => a.path.Equals(path, StringComparison.OrdinalIgnoreCase))) continue;
                string name;
                try { name = System.IO.Path.GetFileNameWithoutExtension(path); }
                catch { name = path; }
                _all.Add((path, name));
            }
            _all.Sort((a, b) => string.Compare(a.name, b.name, StringComparison.OrdinalIgnoreCase));
            RebuildList();
        };
    }

    public static List<string>? Show(Window owner, IEnumerable<string> selected)
    {
        var w = new AppPickerWindow(owner, selected);
        return w.ShowDialog() == true ? w._result : null;
    }

    private void RebuildList()
    {
        string q = _filter.Text.Trim();
        _list.Items.Clear();
        foreach (var (path, name) in _all)
        {
            if (q.Length > 0
                && name.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0
                && path.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0)
                continue;

            var cb = new CheckBox
            {
                Content = $"{name}  —  {path}",
                IsChecked = _selected.Contains(path),
                Tag = path,
                Margin = new Thickness(4, 2, 4, 2),
            };
            cb.Checked += (_, _) => _selected.Add(path);
            cb.Unchecked += (_, _) => _selected.Remove(path);
            _list.Items.Add(cb);
        }
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*",
            Title = Loc.T("AppsBrowse"),
            Multiselect = true,
        };
        if (dlg.ShowDialog(this) != true) return;
        foreach (var f in dlg.FileNames)
        {
            var path = ProcessAppMap.NormalizePath(f);
            if (path.Length == 0) continue;
            _selected.Add(path);
            if (!_all.Any(a => a.path.Equals(path, StringComparison.OrdinalIgnoreCase)))
            {
                string name;
                try { name = System.IO.Path.GetFileNameWithoutExtension(path); }
                catch { name = path; }
                _all.Add((path, name));
            }
        }
        _all.Sort((a, b) => string.Compare(a.name, b.name, StringComparison.OrdinalIgnoreCase));
        RebuildList();
    }

    private void OnOk(object sender, RoutedEventArgs e)
    {
        _result = _selected.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
        DialogResult = true;
    }
}
