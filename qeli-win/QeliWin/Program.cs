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
        // Restore any kill-switch a crashed prior run left in place (best-effort;
        // needs admin — a no-op when unelevated, and the elevated tunnel process
        // sweeps too). Must run before anything touches the network.
        try { Vpn.KillSwitch.Sweep(); } catch { }

        if (args.Any(a => string.Equals(a, "--service", StringComparison.OrdinalIgnoreCase)))
        {
            Service.ServiceHostRunner.Run();
            return 0;
        }

        var app = new App();
        app.InitializeComponent();
        return app.Run();
    }
}
