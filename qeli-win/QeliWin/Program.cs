namespace QeliWin;

/// <summary>
/// Entry point. "--service" runs the headless Windows Service host (session 0, no GUI);
/// anything else launches the WPF app (which itself handles CLI verbs and --autostart).
/// </summary>
public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        // Restore any kill-switch a crashed prior run left in place. A desktop launch may be
        // unelevated and can continue to the UI, but the privileged service must not start a
        // new generation after a failed recovery and overwrite its restoration journal.
        Exception? killSwitchRecoveryFailure = null;
        try { Vpn.KillSwitch.Sweep(message => Console.Error.WriteLine($"qeli: {message}")); }
        catch (Exception error)
        {
            killSwitchRecoveryFailure = error;
            try { Console.Error.WriteLine($"qeli: kill-switch recovery failed: {error}"); } catch { }
        }

        if (args.Any(a => string.Equals(a, "--service", StringComparison.OrdinalIgnoreCase)))
        {
            if (killSwitchRecoveryFailure != null) return 1;
            Service.ServiceHostRunner.Run();
            return 0;
        }

        var app = new App();
        app.InitializeComponent();
        return app.Run();
    }
}
