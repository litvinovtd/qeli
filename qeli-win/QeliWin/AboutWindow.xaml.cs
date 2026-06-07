using System.Reflection;
using System.Windows;

namespace QeliWin;

public partial class AboutWindow : Window
{
    public AboutWindow(Window owner)
    {
        InitializeComponent();
        Owner = owner;
        Icon = owner.Icon;
        LogoImage.Source = Ui.Png(Branding.AppIconPng(96));
        VersionLabel.Text = Loc.F("AboutVersion", AppVersion());
    }

    public static string AppVersion()
    {
        var v = Assembly.GetExecutingAssembly().GetName().Version;
        return v == null ? "—" : $"{v.Major}.{v.Minor}.{v.Build}";
    }

    private void OnOk(object sender, RoutedEventArgs e) => Close();
}
