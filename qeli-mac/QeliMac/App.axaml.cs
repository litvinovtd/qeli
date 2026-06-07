using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using QeliMac.Model;

namespace QeliMac;

public partial class App : Application
{
    // Held so the window (and its tray icon) survive even when started hidden.
    private static MainWindow? _mainWindow;

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
                var settings = AppSettings.Current;
                Loc.SetLanguage(settings.Language);
                Toast.Enabled = settings.ToastsEnabled;

                bool autostart = desktop.Args?.Any(a => a.Equals("--autostart", StringComparison.OrdinalIgnoreCase)) == true;
                bool minimized = autostart || settings.StartMinimized;

                var win = new MainWindow();
                _mainWindow = win;
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
}
