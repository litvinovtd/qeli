using Avalonia.Controls;
using Avalonia.Interactivity;
using QeliMac.Model;
using QRCoder;

namespace QeliMac;

public partial class QrShareWindow : Window
{
    private readonly string _link = "";

    public QrShareWindow() => InitializeComponent();

    public QrShareWindow(Window owner, VpnConfig profile) : this()
    {
        Icon = owner.Icon;
        HeaderText.Text = profile.DisplayName;
        _link = profile.ToQeliUri();
        LinkBox.Text = _link;
        QrImage.Source = Ui.Png(MakeQrPng(_link));
    }

    public static Task ShowAsync(Window owner, VpnConfig profile) =>
        new QrShareWindow(owner, profile).ShowDialog(owner);

    private static byte[] MakeQrPng(string text)
    {
        using var gen = new QRCodeGenerator();
        using var data = gen.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        return new PngByteQRCode(data).GetGraphic(10); // 10 px per module, black on white
    }

    private async void OnCopy(object? sender, RoutedEventArgs e)
    {
        var clip = Avalonia.Controls.TopLevel.GetTopLevel(this)?.Clipboard;
        if (clip != null) { await clip.SetTextAsync(_link); CopyBtn.Content = Loc.T("Copied"); }
    }

    private void OnClose(object? sender, RoutedEventArgs e) => Close();
}
