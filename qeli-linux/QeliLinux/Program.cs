using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
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
    public override void Initialize() => AvaloniaXamlLoader.Load(this);
    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            desktop.MainWindow = new MainWindow();
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
    private Process? runner;
    private bool busy;
    private bool closing;

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
            if (closing || runner is null) return;
            args.Cancel = true;
            await StopAsync();
            if (runner is null) { closing = true; Close(); }
        };
        TryAction(() =>
        {
            Directory.CreateDirectory(directory);
            if (OperatingSystem.IsLinux()) File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Refresh();
        });
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
        status.Text = "Profile saved";
    }

    private void Refresh() => profiles.ItemsSource = Directory.GetFiles(directory, "*.conf")
        .Select(Path.GetFileNameWithoutExtension).Order().ToArray();

    private void TryAction(Action action)
    {
        try { action(); }
        catch (Exception error) { status.Text = error.Message; }
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

    private async Task StartAsync()
    {
        if (busy || runner is not null) return;
        busy = true;
        start.IsEnabled = false;
        try
        {
            if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("VPN requires Linux, systemd and polkit.");
            var config = Parse();
            if (config.AppsMode != "all") throw new InvalidOperationException("Per-app routing is not supported by this Linux desktop client.");
            var clientPath = File.Exists("/usr/libexec/qeli-linux/qeli-client")
                ? "/usr/libexec/qeli-linux/qeli-client" : "/usr/local/bin/qeli-client";
            if (!File.Exists(clientPath)) throw new FileNotFoundException("Install the qeli-linux package or qeli-client in /usr/local/bin first.");
            var process = CreateProcess("/usr/bin/systemd-run", "--quiet", "--pipe", "--wait", "--collect",
                $"--unit={unit}", "--property=KillSignal=SIGINT", "--property=TimeoutStopSec=30",
                clientPath, "--config", "/dev/stdin");
            process.Start();
            runner = process;
            stop.IsEnabled = true;
            status.Text = "Starting VPN process";
            var output = DrainAsync(process.StandardOutput);
            var errors = DrainAsync(process.StandardError);
            await process.StandardInput.WriteAsync(config.ToIni());
            process.StandardInput.Close();
            busy = false;
            await process.WaitForExitAsync();
            await Task.WhenAll(output, errors);
            status.Text = process.ExitCode == 0 ? "Stopped" : $"VPN process exited ({process.ExitCode}). See journal.";
        }
        catch (Exception error) { status.Text = error.Message; }
        finally
        {
            runner?.Dispose();
            runner = null;
            busy = false;
            start.IsEnabled = true;
            stop.IsEnabled = false;
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

    private async Task StopAsync()
    {
        if (runner is null || busy) return;
        stop.IsEnabled = false;
        try
        {
            using var process = CreateProcess("/usr/bin/systemctl", "stop", unit + ".service");
            process.Start();
            process.StandardInput.Close();
            var output = process.StandardOutput.ReadToEndAsync();
            var errors = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            await output;
            if (process.ExitCode != 0) throw new InvalidOperationException(await errors);
            var active = runner;
            if (active is not null) await active.WaitForExitAsync();
        }
        catch (Exception error) { status.Text = error.Message; }
        finally { stop.IsEnabled = runner is not null; }
    }
}