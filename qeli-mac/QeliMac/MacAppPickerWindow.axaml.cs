using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;

namespace QeliMac;

/// <summary>Lists installed macOS application bundles and returns their code-signing
/// identifiers. Existing identifiers absent from this Mac remain visible/selectable so a
/// portable profile never loses Android, Windows or temporarily-uninstalled entries.</summary>
public partial class MacAppPickerWindow : Window
{
    private HashSet<string> _selected = new(StringComparer.Ordinal);
    private readonly List<AppRow> _all = new();
    private readonly ObservableCollection<AppRow> _visible = new();
    private List<string>? _result;

    public MacAppPickerWindow()
    {
        InitializeComponent();
        AppsList.ItemsSource = _visible;
    }

    private MacAppPickerWindow(
        Window owner,
        IEnumerable<string> selected,
        IEnumerable<(string identifier, string name, string bundlePath)> installed) : this()
    {
        Icon = owner.Icon;
        _selected = new HashSet<string>(
            selected.Select(v => v.Trim()).Where(v => v.Length > 0),
            StringComparer.Ordinal);
        foreach (var app in installed)
            _all.Add(MakeRow(app.identifier, app.name, app.bundlePath));
        foreach (string identifier in _selected)
        {
            if (_all.Any(a => a.Identifier.Equals(identifier, StringComparison.Ordinal))) continue;
            _all.Add(MakeRow(identifier, identifier, ""));
        }
        _all.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        RebuildList();
    }

    public static async Task<List<string>?> ShowAsync(Window owner, IEnumerable<string> selected)
    {
        var installed = await Task.Run(ListCandidateApps);
        var window = new MacAppPickerWindow(owner, selected, installed);
        await window.ShowDialog(owner);
        return window._result;
    }

    private AppRow MakeRow(string identifier, string name, string path) =>
        new(identifier, name, path, _selected.Contains(identifier), OnRowToggled);

    private void OnRowToggled(AppRow row)
    {
        if (row.IsSelected) _selected.Add(row.Identifier);
        else _selected.Remove(row.Identifier);
    }

    private void RebuildList()
    {
        string query = FilterBox.Text?.Trim() ?? "";
        _visible.Clear();
        foreach (var row in _all)
        {
            if (query.Length > 0
                && row.Name.IndexOf(query, StringComparison.OrdinalIgnoreCase) < 0
                && row.Identifier.IndexOf(query, StringComparison.OrdinalIgnoreCase) < 0
                && row.BundlePath.IndexOf(query, StringComparison.OrdinalIgnoreCase) < 0)
                continue;
            _visible.Add(row);
        }
    }

    private void OnFilterChanged(object? sender, TextChangedEventArgs e) => RebuildList();
    private void OnCancel(object? sender, RoutedEventArgs e) => Close();

    private void OnOk(object? sender, RoutedEventArgs e)
    {
        _result = _selected.OrderBy(v => v, StringComparer.OrdinalIgnoreCase).ToList();
        Close();
    }

    private static List<(string identifier, string name, string bundlePath)> ListCandidateApps()
    {
        var result = new List<(string, string, string)>();
        if (!OperatingSystem.IsMacOS()) return result;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        foreach (string root in new[]
        {
            "/Applications",
            "/System/Applications",
            Path.Combine(home, "Applications"),
        })
        {
            foreach (string bundle in EnumerateBundles(root, maxDepth: 4))
            {
                string? identifier = ReadSigningIdentifier(bundle) ?? ReadBundleIdentifier(bundle);
                if (string.IsNullOrWhiteSpace(identifier) || !seen.Add(identifier)) continue;
                string name = Path.GetFileNameWithoutExtension(bundle);
                result.Add((identifier, name, bundle));
            }
        }
        return result;
    }

    private static IEnumerable<string> EnumerateBundles(string root, int maxDepth)
    {
        if (!Directory.Exists(root)) yield break;
        var pending = new Stack<(string path, int depth)>();
        pending.Push((root, 0));
        while (pending.Count > 0)
        {
            var (path, depth) = pending.Pop();
            IEnumerable<string> children;
            try { children = Directory.EnumerateDirectories(path).ToArray(); }
            catch { continue; }
            foreach (string child in children)
            {
                if (child.EndsWith(".app", StringComparison.OrdinalIgnoreCase))
                {
                    yield return child;
                    continue;
                }
                if (depth < maxDepth) pending.Push((child, depth + 1));
            }
        }
    }

    private static string? ReadSigningIdentifier(string bundle)
    {
        try
        {
            var psi = new ProcessStartInfo("/usr/bin/codesign")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("-dv");
            psi.ArgumentList.Add("--verbose=4");
            psi.ArgumentList.Add(bundle);
            using var process = Process.Start(psi);
            if (process == null) return null;
            Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            Task<string> stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(3000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return null;
            }
            string details = stdout.GetAwaiter().GetResult() + "\n" + stderr.GetAwaiter().GetResult();
            const string prefix = "Identifier=";
            string? line = details.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(value => value.Trim())
                .FirstOrDefault(value => value.StartsWith(prefix, StringComparison.Ordinal));
            return line?[prefix.Length..].Trim();
        }
        catch { return null; }
    }

    private static string? ReadBundleIdentifier(string bundle)
    {
        string plist = Path.Combine(bundle, "Contents", "Info.plist");
        if (!File.Exists(plist)) return null;
        try
        {
            var psi = new ProcessStartInfo("/usr/bin/plutil")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            foreach (string arg in new[] { "-extract", "CFBundleIdentifier", "raw", "-o", "-", plist })
                psi.ArgumentList.Add(arg);
            using var process = Process.Start(psi);
            if (process == null) return null;
            string value = process.StandardOutput.ReadToEnd();
            _ = process.StandardError.ReadToEnd();
            if (!process.WaitForExit(2000) || process.ExitCode != 0) return null;
            return value.Trim();
        }
        catch { return null; }
    }

    private sealed class AppRow : INotifyPropertyChanged
    {
        private readonly Action<AppRow> _onToggled;
        private bool _isSelected;
        public string Identifier { get; }
        public string Name { get; }
        public string BundlePath { get; }
        public bool IsSelected
        {
            get => _isSelected;
            set
            {
                if (_isSelected == value) return;
                _isSelected = value;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
                _onToggled(this);
            }
        }

        public AppRow(string identifier, string name, string bundlePath, bool selected,
                      Action<AppRow> onToggled)
        {
            Identifier = identifier;
            Name = name;
            BundlePath = bundlePath;
            _isSelected = selected;
            _onToggled = onToggled;
        }

        public event PropertyChangedEventHandler? PropertyChanged;
    }
}
