using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Threading;
using Qeli.Shared;
using QeliWin.Service;

namespace QeliWin;

public partial class App : Application
{
    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int processId);
    private const int AttachParentProcess = -1;

    internal static void AttachParentConsoleForCli() => AttachConsole(AttachParentProcess);

    private static readonly string[] CliVerbs = { "selftest", "packetbench", "handshake", "connect", "genassets", "uishot", "editshot", "mainshot" };

    protected override void OnStartup(StartupEventArgs e)
    {
        if (e.Args.Length > 0 && CliVerbs.Contains(e.Args[0].ToLowerInvariant()))
        {
            AttachParentConsoleForCli();
            Console.WriteLine();
            int code = CliRunner.Run(e.Args[0], e.Args.Skip(1).ToArray());
            Console.Out.Flush();
            Shutdown(code);
            return;
        }

        DispatcherUnhandledException += OnUnhandled;
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandled;
        TaskScheduler.UnobservedTaskException += OnUnobservedTask;
        // Exit only via the tray "Выход" — closing/minimizing the window goes to tray,
        // and "service mode" runs with no window shown.
        ShutdownMode = ShutdownMode.OnExplicitShutdown;
        ThemeManager.Apply();   // palette from the live Windows theme + accent

        var settings = Model.AppSettings.Current;
        Loc.SetLanguage(settings.Language);
        Toast.Enabled = settings.ToastsEnabled;
        base.OnStartup(e);

        bool autostart = e.Args.Any(a => a.Equals("--autostart", StringComparison.OrdinalIgnoreCase));
        bool minimized = autostart || settings.StartMinimized;

        var win = new MainWindow();
        if (!minimized) win.Show();
        win.RunStartupActions();
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        RecordUnhandled("WPF dispatcher", e.Exception, terminating: true);
        MessageBox.Show(e.Exception.ToString(), Loc.T("UnhandledError"),
            MessageBoxButton.OK, MessageBoxImage.Error);
        // Continuing after an unhandled async-void/UI exception can leave the tunnel,
        // kill-switch and visible state disagreeing. The durable log is written first;
        // let WPF terminate the corrupted process and normal startup recovery clean up.
        e.Handled = false;
    }

    private static void OnAppDomainUnhandled(object sender, UnhandledExceptionEventArgs e)
    {
        var error = e.ExceptionObject as Exception
            ?? new InvalidOperationException($"Non-Exception unhandled object: {e.ExceptionObject}");
        RecordUnhandled("AppDomain", error, e.IsTerminating);
    }

    private static void OnUnobservedTask(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        RecordUnhandled("unobserved Task", e.Exception, terminating: false);
        // Modern .NET normally suppresses process termination here. Marking the exception
        // observed after persisting it prevents a future runtime-policy change from turning
        // a diagnostic-only background failure into an unrelated finalizer-thread crash.
        e.SetObserved();
    }

    private static void RecordUnhandled(string source, Exception error, bool terminating)
    {
        ServiceState.AppendLog(
            $"UNHANDLED [{source}] terminating={terminating}: {error}");
        try { Console.Error.WriteLine($"qeli: unhandled [{source}]: {error}"); }
        catch { /* the durable file log above is the primary sink */ }
    }
}
