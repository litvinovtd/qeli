using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Threading;
using Qeli.Shared.Model;
using QeliLinux;
using System.Runtime.InteropServices;

// No graphical session, native core, polkit authorization or VPN is used here.
AppBuilder.Configure<App>().UseHeadless(new AvaloniaHeadlessPlatformOptions())
    .SetupWithoutStarting();
int checks = 0;
void Check(string name, bool passed)
{
    if (!passed) throw new InvalidOperationException("FAIL: " + name);
    Console.WriteLine("PASS: " + name);
    checks++;
}

var window = new MainWindow();
window.Show();
var closeToTray = window.FindControl<CheckBox>("CloseToTray")!;
Check("close-to-tray is opt-in", closeToTray.IsChecked == false);
Check("close-to-tray unavailable without platform support", !closeToTray.IsEnabled);
Check("initial VPN controls", window.CanStart && !window.CanStop);

window.SetTrayAvailable(true);
Check("tray option enabled with platform support", closeToTray.IsEnabled);
closeToTray.IsChecked = true;
bool closed = false;
window.Closed += (_, _) => closed = true;
window.Close();
Dispatcher.UIThread.RunJobs();
Check("closing to tray hides without destroying the window", !window.IsVisible && !closed);

window.ShowFromTray();
Check("tray action restores window", window.IsVisible && !closed);
window.WindowState = WindowState.Minimized;
window.ShowFromTray();
Check("tray action restores minimized window", window.WindowState == WindowState.Normal);

// Even if the option was checked, losing platform support must not hide a window.
window.SetTrayAvailable(false);
window.Close();
Dispatcher.UIThread.RunJobs();
Check("closing without tray support exits", closed);

var explicitExit = new MainWindow();
explicitExit.SetTrayAvailable(true);
explicitExit.FindControl<CheckBox>("CloseToTray")!.IsChecked = true;
explicitExit.Show();
bool explicitlyClosed = false;
explicitExit.Closed += (_, _) => explicitlyClosed = true;
explicitExit.RequestExitAsync().GetAwaiter().GetResult();
Dispatcher.UIThread.RunJobs();
Check("explicit exit overrides close-to-tray", explicitlyClosed);
Check("exit prevents new VPN starts", !explicitExit.CanStart && !explicitExit.CanStop);
if (args.Length == 1)
{
    NativeLibrary.SetDllImportResolver(typeof(VpnConfig).Assembly,
        (name, assembly, searchPath) => name == "qeli"
            ? NativeLibrary.Load(Path.GetFullPath(args[0])) : IntPtr.Zero);
    var imported = VpnConfig.FromIni("[qeli]\nserver=192.0.2.1:443\nmode=plain\n"
        + "bind_static=false\ngateway=false\nuser=fixture\npass=fixture-only\n");
    Check("packaged native core imports current INI", imported.ServerAddress == "192.0.2.1"
        && imported.Username == "fixture");
    var restored = VpnConfig.FromIni(imported.ToIni());
    Check("packaged native core round-trips profiles", restored.Password == "fixture-only"
        && restored.Protocol == imported.Protocol);
    var link = VpnConfig.FromQeliUri("qeli://fixture:fixture-only@192.0.2.1:443?proto=tcp&mode=plain");
    Check("packaged native core imports share links", link.Username == "fixture"
        && link.ServerAddress == "192.0.2.1" && link.Protocol == "tcp");
}
Console.WriteLine($"All {checks} headless lifecycle checks passed.");
