using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Platform;
using Avalonia.Threading;
using Qeli.Shared.Model;
using System.Diagnostics;

namespace QeliLinux;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args) => AppBuilder.Configure<App>()
        .UsePlatformDetect().StartWithClassicDesktopLifetime(args);
}

public sealed partial class App : Application
{
    private TrayIcon? tray;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);
    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var window = new MainWindow();
            desktop.MainWindow = window;
            var open = new NativeMenuItem("Open Qeli");
            var start = new NativeMenuItem("Start VPN");
            var stop = new NativeMenuItem("Stop VPN");
            var exit = new NativeMenuItem("Exit Qeli");
            open.Click += (_, _) => window.ShowFromTray();
            start.Click += async (_, _) => { window.ShowFromTray(); await window.StartAsync(); };
            stop.Click += async (_, _) => { window.ShowFromTray(); await window.StopAsync(); };
            exit.Click += async (_, _) => { window.ShowFromTray(); await window.RequestExitAsync(); };
            var menu = new NativeMenu();
            menu.Items.Add(open);
            menu.Items.Add(new NativeMenuItemSeparator());
            menu.Items.Add(start);
            menu.Items.Add(stop);
            menu.Items.Add(new NativeMenuItemSeparator());
            menu.Items.Add(exit);
            using var icon = AssetLoader.Open(new Uri("avares://QeliLinux/Assets/qeli-logo.png"));
            tray = new TrayIcon { Icon = new WindowIcon(icon), Menu = menu, IsVisible = true };
            TrayIcon.SetIcons(this, new TrayIcons { tray });
            tray.Clicked += (_, _) => window.ShowFromTray();
            // An exporter means the platform supports tray menus, not that the DE
            // actually displays them (GNOME requires an extension). Hiding is opt-in.
            window.SetTrayAvailable(tray.NativeMenuExporter is not null);
            void UpdateTray()
            {
                tray.ToolTipText = "Qeli · " + window.StatusText;
                start.IsEnabled = window.CanStart;
                stop.IsEnabled = window.CanStop;
            }
            window.StateChanged += (_, _) => UpdateTray();
            UpdateTray();
            desktop.Exit += (_, _) => { tray.Dispose(); tray = null; };
        }
        base.OnFrameworkInitializationCompleted();
    }
}

public sealed partial class MainWindow : Window
{
    private readonly string directory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "qeli-linux");
    private readonly string unit = $"qeli-desktop-{Environment.ProcessId}";
    private readonly ListBox profiles;
    private readonly TextBox editor;
    private readonly TextBox profileName;
    private readonly TextBlock status;
    private readonly TextBox journal;
    private readonly Button start;
    private readonly Button stop;
    private readonly CheckBox closeToTray;
    private Process? runner;
    private Task? runningTask;
    private bool busy;
    private bool stopping;
    private bool exiting;
    private bool closing;
    private bool trayAvailable;

    public event EventHandler? StateChanged;
    public bool CanStart => !busy && !stopping && !exiting && runner is null;
    public bool CanStop => !busy && !stopping && !exiting && runner is not null;
    public string StatusText => status.Text ?? "Stopped";

    public MainWindow()
    {
        AvaloniaXamlLoader.Load(this);
        profiles = this.FindControl<ListBox>("Profiles")!;
        editor = this.FindControl<TextBox>("Editor")!;
        profileName = this.FindControl<TextBox>("ProfileName")!;
        status = this.FindControl<TextBlock>("Status")!;
        journal = this.FindControl<TextBox>("Journal")!;
        start = this.FindControl<Button>("StartVpn")!;
        stop = this.FindControl<Button>("StopVpn")!;
        closeToTray = this.FindControl<CheckBox>("CloseToTray")!;
        this.FindControl<Button>("ExitApp")!.Click += async (_, _) => await RequestExitAsync();
        var save = this.FindControl<Button>("SaveProfile")!;
        var remove = this.FindControl<Button>("DeleteProfile")!;
        profiles.SelectionChanged += (_, _) =>
        {
            if (profiles.SelectedItem is not string name) return;
            TryAction(() =>
            {
                editor.Text = File.ReadAllText(Path.Combine(directory, name + ".conf"));
                profileName.Text = name;
            });
        };
        save.Click += (_, _) => TryAction(Save);
        remove.Click += (_, _) => TryAction(() =>
        {
            if (profiles.SelectedItem is string name)
                File.Delete(Path.Combine(directory, name + ".conf"));
            Refresh();
        });
        start.Click += async (_, _) => await StartAsync();
        stop.Click += async (_, _) => await StopAsync();
        Closing += async (_, args) =>
        {
            if (closing) return;
            args.Cancel = true;
            if (!exiting && trayAvailable && closeToTray.IsChecked == true) Hide();
            else await RequestExitAsync();
        };
        TryAction(() =>
        {
            Directory.CreateDirectory(directory);
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Refresh();
        });
    }

    public void SetTrayAvailable(bool available)
    {
        trayAvailable = available;
        closeToTray.IsEnabled = available;
    }

    public void ShowFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
    }

    private void SetStatus(string text)
    {
        status.Text = text;
        UpdateControls();
    }

    private void UpdateControls()
    {
        start.IsEnabled = CanStart;
        stop.IsEnabled = CanStop;
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task RequestExitAsync()
    {
        if (exiting) return;
        if (busy || stopping)
        {
            ShowFromTray();
            SetStatus("Wait for the current VPN operation, then exit again.");
            return;
        }
        exiting = true;
        UpdateControls();
        if (runner is not null && !await StopAsync())
        {
            exiting = false;
            ShowFromTray();
            UpdateControls();
            return;
        }
        closing = true;
        Close();
    }

    private VpnConfig Parse()
    {
        var text = (editor.Text ?? "").Trim();
        if (text.Length == 0) throw new InvalidOperationException("Paste a qeli:// link or INI configuration.");
        return text.StartsWith("qeli://", StringComparison.OrdinalIgnoreCase)
            ? VpnConfig.FromQeliUri(text) : VpnConfig.FromIni(text);
    }

    private void Save()
    {
        var config = Parse();
        var name = (profileName.Text ?? "").Trim();
        if (name.Length == 0 || name.Length > 80 || name.Any(character => !char.IsLetterOrDigit(character) && character != '-' && character != '_'))
            throw new InvalidOperationException("Use letters, digits, '-' or '_' in the profile name (1–80 characters).");
        var path = Path.Combine(directory, name + ".conf");
        var options = new FileStreamOptions
        {
            Mode = FileMode.Create, Access = FileAccess.Write
        };
        if (OperatingSystem.IsLinux()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var stream = new FileStream(path, options))
        using (var writer = new StreamWriter(stream)) writer.Write(config.ToIni());
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        editor.Text = config.ToIni();
        Refresh();
        SetStatus("Profile saved");
    }

    private void Refresh() => profiles.ItemsSource = Directory.GetFiles(directory, "*.conf")
        .Select(Path.GetFileNameWithoutExtension).Order().ToArray();

    private void TryAction(Action action)
    {
        try { action(); }
        catch (Exception error) { SetStatus(error.Message); }
    }

    private static Process CreateProcess(params string[] arguments)
    {
        var info = new ProcessStartInfo("/usr/bin/pkexec")
        {
            UseShellExecute = false, RedirectStandardInput = true,
            RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        return new Process { StartInfo = info };
    }

    public async Task StartAsync()
    {
        if (!CanStart) return;
        busy = true;
        UpdateControls();
        try
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("VPN requires Linux, systemd and polkit.");
            var config = Parse();
            if (config.AppsMode != "all") throw new InvalidOperationException("Per-app routing is not supported by this Linux desktop client.");
            var clientPath = File.Exists("/usr/libexec/qeli-linux/qeli-client")
                ? "/usr/libexec/qeli-linux/qeli-client" : "/usr/local/bin/qeli-client";
            if (!File.Exists(clientPath)) throw new FileNotFoundException("Install the qeli-linux package or qeli-client in /usr/local/bin first.");
            const string launcherPath = "/usr/libexec/qeli-linux/launch-client";
            if (!File.Exists(launcherPath)) throw new FileNotFoundException("Install the Qeli Linux launch-client helper first.");
            var process = CreateProcess("/usr/bin/systemd-run", "--quiet", "--pipe", "--wait", "--collect",
                $"--unit={unit}", "--property=KillSignal=SIGINT", "--property=TimeoutStopSec=30",
                $"--property=RuntimeDirectory={unit}", "--property=RuntimeDirectoryMode=0700",
                "--property=UMask=0077", launcherPath, clientPath);
            try { process.Start(); }
            catch { process.Dispose(); throw; }
            runner = process;
            SetStatus("VPN process running / awaiting authorization (not tunnel readiness)");
            var output = DrainAsync(process.StandardOutput);
            var errors = DrainAsync(process.StandardError);
            runningTask = ObserveRunnerAsync(process, output, errors);
            await process.StandardInput.WriteAsync(config.ToIni());
            process.StandardInput.Close();
        }
        catch (Exception error)
        {
            busy = false;
            if (runner is not null) await StopAsync();
            SetStatus(error.Message);
        }
        finally
        {
            busy = false;
            UpdateControls();
        }
    }

    private async Task ObserveRunnerAsync(Process process, Task output, Task errors)
    {
        try
        {
            await process.WaitForExitAsync();
            await Task.WhenAll(output, errors);
            SetStatus(process.ExitCode == 0 ? "Stopped" : $"VPN process exited ({process.ExitCode}). See journal.");
        }
        catch (Exception error) { SetStatus(error.Message); }
        finally
        {
            process.Dispose();
            runner = null;
            UpdateControls();
        }
    }

    private async Task DrainAsync(StreamReader reader)
    {
        while (await reader.ReadLineAsync() is { } line)
            await Dispatcher.UIThread.InvokeAsync(() =>
            {
                var text = journal.Text + line + Environment.NewLine;
                journal.Text = text.Length > 16000 ? text[^16000..] : text;
            });
    }

    public async Task<bool> StopAsync()
    {
        if (runner is null) return true;
        if (busy || stopping) return false;
        stopping = true;
        UpdateControls();
        try
        {
            var completion = runningTask;
            using var process = CreateProcess("/usr/bin/systemctl", "stop", unit + ".service");
            process.Start();
            process.StandardInput.Close();
            var output = process.StandardOutput.ReadToEndAsync();
            var errors = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            await output;
            var errorText = await errors;
            // Authentication cancellation can race with an independently exiting client.
            if (process.ExitCode != 0 && runner is not null)
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(errorText)
                    ? $"Stopping VPN failed ({process.ExitCode})." : errorText);
            if (completion is not null) await completion;
            return runner is null;
        }
        catch (Exception error) { SetStatus(error.Message); return false; }
        finally { stopping = false; UpdateControls(); }
    }
}
