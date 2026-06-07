using System.Windows;
using QeliWin.Model;
using QRCoder;

namespace QeliWin;

public partial class QrShareWindow : Window
{
    private readonly string _link;

    public QrShareWindow(Window owner, VpnConfig profile)
    {
        InitializeComponent();
        Owner = owner;
        Icon = owner.Icon;
        HeaderText.Text = profile.DisplayName;

        _link = profile.ToQeliUri();
        LinkBox.Text = _link;
        QrImage.Source = Ui.Png(MakeQrPng(_link));
    }

    public static void Show(Window owner, VpnConfig profile) => new QrShareWindow(owner, profile).ShowDialog();

    private static byte[] MakeQrPng(string text)
    {
        using var gen = new QRCodeGenerator();
        using var data = gen.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        return new PngByteQRCode(data).GetGraphic(10); // 10 px per module, black on white
    }

    private void OnCopy(object sender, RoutedEventArgs e)
    {
        try { Clipboard.SetText(_link); CopyBtn.Content = Loc.T("Copied"); } catch { }
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
