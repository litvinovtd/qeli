using System.Reflection;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Qeli.Shared;

namespace QeliMac;

public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        LogoImage.Source = Ui.Png(Branding.AppIconPng(96));
        VersionLabel.Text = Loc.F("AboutVersion", AppVersion());
    }

    public AboutWindow(Window owner) : this() => Icon = owner.Icon;

    public static string AppVersion()
    {
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        return v == null ? "—" : $"{v.Major}.{v.Minor}.{v.Build}";
    }

    private void OnOk(object? sender, RoutedEventArgs e) => Close();
}
