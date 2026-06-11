using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Threading;
using Qeli.Shared;

namespace QeliWin;

public partial class App : Application
{
    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int processId);
    private const int AttachParentProcess = -1;

    private static readonly string[] CliVerbs = { "selftest", "handshake", "connect", "genassets", "uishot", "editshot", "mainshot" };

    protected override void OnStartup(StartupEventArgs e)
    {
        if (e.Args.Length > 0 && CliVerbs.Contains(e.Args[0].ToLowerInvariant()))
        {
            AttachConsole(AttachParentProcess);
            Console.WriteLine();
            int code = CliRunner.Run(e.Args[0], e.Args.Skip(1).ToArray());
            Console.Out.Flush();
            Shutdown(code);
            return;
        }

        DispatcherUnhandledException += OnUnhandled;
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
        MessageBox.Show(e.Exception.ToString(), Loc.T("UnhandledError"),
            MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
