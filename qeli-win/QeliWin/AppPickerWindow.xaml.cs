using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using Qeli.Shared;
using QeliWin.Vpn;

namespace QeliWin;

/// <summary>Pick .exe paths for per-app split tunnelling. Lists currently running
/// non-system processes; returns the selected full paths (or null on cancel).</summary>
public partial class AppPickerWindow : Window
{
    private readonly HashSet<string> _selected;
    private readonly List<AppRow> _all = new();
    private readonly ObservableCollection<AppRow> _visible = new();
    private List<string>? _result;

    public AppPickerWindow(Window owner, IEnumerable<string> selected)
    {
        InitializeComponent();
        Owner = owner;
        Icon = owner.Icon;

        _selected = new HashSet<string>(
            selected.Select(ProcessAppMap.NormalizePath).Where(p => p.Length > 0),
            StringComparer.OrdinalIgnoreCase);

        AppsList.ItemsSource = _visible;

        Loaded += (_, _) =>
        {
            foreach (var (path, name) in ProcessAppMap.ListCandidateApps())
                _all.Add(MakeRow(path, name));

            // Keep manually-selected paths that are not currently running.
            foreach (var path in _selected)
            {
                if (_all.Any(a => a.FullPath.Equals(path, StringComparison.OrdinalIgnoreCase))) continue;
                string name;
                try { name = System.IO.Path.GetFileNameWithoutExtension(path); }
                catch { name = path; }
                _all.Add(MakeRow(path, name));
            }

            _all.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
            RebuildList();
        };
    }

    public static List<string>? Show(Window owner, IEnumerable<string> selected)
    {
        var w = new AppPickerWindow(owner, selected);
        return w.ShowDialog() == true ? w._result : null;
    }

    private AppRow MakeRow(string path, string name) => new(path, name, _selected.Contains(path), OnRowToggled);

    private void OnRowToggled(AppRow row)
    {
        if (row.IsSelected) _selected.Add(row.FullPath);
        else _selected.Remove(row.FullPath);
    }

    private void RebuildList()
    {
        string q = FilterBox.Text.Trim();
        _visible.Clear();
        foreach (var row in _all)
        {
            if (q.Length > 0
                && row.Name.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0
                && row.FullPath.IndexOf(q, StringComparison.OrdinalIgnoreCase) < 0)
                continue;
            _visible.Add(row);
        }
    }

    private void OnFilterChanged(object sender, TextChangedEventArgs e) => RebuildList();

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
            var existing = _all.FirstOrDefault(a => a.FullPath.Equals(path, StringComparison.OrdinalIgnoreCase));
            if (existing != null)
            {
                existing.IsSelected = true;
                continue;
            }
            string name;
            try { name = System.IO.Path.GetFileNameWithoutExtension(path); }
            catch { name = path; }
            _all.Add(MakeRow(path, name));
        }
        _all.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        RebuildList();
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;

    private void OnOk(object sender, RoutedEventArgs e)
    {
        _result = _selected.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
        DialogResult = true;
    }

    private sealed class AppRow : INotifyPropertyChanged
    {
        private readonly Action<AppRow> _onToggled;
        private bool _isSelected;

        public string FullPath { get; }
        public string Name { get; }

        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected == value) return;
                _isSelected = value;
                OnPropertyChanged();
                _onToggled(this);
            }
        }

        public AppRow(string path, string name, bool selected, Action<AppRow> onToggled)
        {
            FullPath = path;
            Name = name;
            _isSelected = selected;
            _onToggled = onToggled;
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        private void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
