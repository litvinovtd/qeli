using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Qeli.Shared;

namespace QeliWin;

public partial class LicensesWindow : Window
{
    public LicensesWindow(Window owner)
    {
        InitializeComponent();
        Owner = owner;
        Icon = owner.Icon;
        Summary.Text = Loc.F("LicensesSummary", EmbeddedLicenses.Names.Count);
        ResourcesList.ItemsSource = EmbeddedLicenses.Names;
        ResourcesList.SelectedItem = "rust/Qeli-AGPL-3.0.txt";
    }

    private void OnSelected(object sender, SelectionChangedEventArgs e)
    {
        if (ResourcesList.SelectedItem is not string name) return;
        LicenseText.Text = Encoding.UTF8.GetString(EmbeddedLicenses.Read(name));
        LicenseText.ScrollToHome();
    }

    private void OnExport(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { FileName = "qeli-licenses-" + AboutWindow.AppVersion() + ".zip", Filter = "ZIP (*.zip)|*.zip", OverwritePrompt = true };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            using var output = new FileStream(dialog.FileName, FileMode.Create, FileAccess.Write);
            EmbeddedLicenses.WriteZip(output);
        }
        catch (Exception error) { MessageBox.Show(this, error.Message, Loc.T("Licenses"), MessageBoxButton.OK, MessageBoxImage.Error); }
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
