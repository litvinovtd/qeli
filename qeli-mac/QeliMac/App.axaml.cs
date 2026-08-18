using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using System.Runtime.InteropServices;
using QeliMac.Model;
using Qeli.Shared;

namespace QeliMac;

public partial class App : Application
{
    // Held so the window (and its tray icon) survive even when started hidden.
    private static MainWindow? _mainWindow;
    // POSIX registrations must stay rooted for the complete GUI lifetime; disposing either
    // one restores the signal's default (immediate-terminate) disposition.
    private PosixSignalRegistration? _sigInt;
    private PosixSignalRegistration? _sigTerm;
    private int _terminationSignalReceived;

    internal void ResetTerminationSignal() =>
        Interlocked.Exchange(ref _terminationSignalReceived, 0);

    /// <summary>Headless screenshot mode (uishot verb): skip the menu-bar tray icon,
    /// which has no native backend when rendering offscreen.</summary>
    public static bool ShotMode { get; set; }

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            try
            {
                // Exit only via the tray "Exit" — closing/minimizing the window goes to tray.
                desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;

                ThemeManager.Apply();                 // palette from the live macOS appearance + accent

                // 0.7.12 changed the bundle id prefix to ru.qeli.app. The login agent is per-user,
                // so it can be carried over silently right here; the root daemon cannot, and is
                // cleared by ServiceManager on the next install/start.
                try { AutoStartManager.MigrateLegacy(); } catch { /* best-effort, never block startup */ }

                var settings = AppSettings.Current;
                Loc.SetLanguage(settings.Language);
                Toast.Enabled = settings.ToastsEnabled;

                bool autostart = desktop.Args?.Any(a => a.Equals("--autostart", StringComparison.OrdinalIgnoreCase)) == true;
                bool minimized = autostart || settings.StartMinimized;

                var win = new MainWindow();
                _mainWindow = win;
                RegisterTerminationSignals(desktop, win);
                if (!minimized) desktop.MainWindow = win; // the lifetime shows it; tray-only otherwise
                win.RunStartupActions();
            }
            catch (Exception e)
            {
                Program.LogStartupError(e); // record the precise failure before the lifetime aborts
                throw;
            }
        }
        base.OnFrameworkInitializationCompleted();
    }

    private void RegisterTerminationSignals(
        IClassicDesktopStyleApplicationLifetime desktop, MainWindow window)
    {
        if (!OperatingSystem.IsMacOS()) return;

        void RequestOrderlyExit(PosixSignalContext context)
        {
            // Without this, SIGINT/SIGTERM terminates the process before VpnTunnel.Stop()
            // can release the persistent networksetup DNS override and host routes.
            context.Cancel = true;
            if (Interlocked.Exchange(ref _terminationSignalReceived, 1) != 0) return;

            // Signal callbacks run off the UI thread. Queue the COMPLETE exit on Avalonia's
            // dispatcher so it is serialized after any in-flight Connect/autoconnect action;
            // otherwise that action could start a tunnel after a concurrent Stop() returned.
            try { Dispatcher.UIThread.Post(window.ExitApp, DispatcherPriority.Send); }
            catch (Exception error)
            {
                // If Avalonia is already unavailable, do not turn the signal into an
                // unkillable no-op. Restore the default disposition for this delivery.
                Program.LogStartupError(new Exception("failed to queue GUI signal teardown", error));
                context.Cancel = false;
            }
        }

        try
        {
            _sigInt = PosixSignalRegistration.Create(PosixSignal.SIGINT, RequestOrderlyExit);
            _sigTerm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, RequestOrderlyExit);
            desktop.Exit += (_, _) => DisposeTerminationSignals();
        }
        catch (Exception error)
        {
            DisposeTerminationSignals();
            Program.LogStartupError(new Exception("failed to register GUI termination signals", error));
        }
    }

    private void DisposeTerminationSignals()
    {
        try { _sigInt?.Dispose(); } catch { }
        try { _sigTerm?.Dispose(); } catch { }
        _sigInt = null;
        _sigTerm = null;
    }
}
