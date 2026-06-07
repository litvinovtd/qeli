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
