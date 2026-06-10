using System.Windows;
using System.Windows.Controls;
using QeliWin.Model;
using Qeli.Shared;
using Qeli.Shared.Model;

namespace QeliWin;

/// <summary>
/// Form-based profile editor: exposes only the fields a user can sensibly set, via
/// dropdowns/inputs, and builds a <see cref="VpnConfig"/> from them (the server pushes
/// the rest). Use <see cref="Show"/>; returns the config or null on cancel.
/// </summary>
public partial class ConfigEditorWindow : Window
{
    private VpnConfig? _result;

    public ConfigEditorWindow(Window owner, VpnConfig? existing)
    {
        InitializeComponent();
        Owner = owner;
        Icon = owner.Icon;

        if (existing == null)
        {
            HeaderText.Text = Loc.T("NewProfileTitle");
            SelectByTag(ModeBox, "faketls");
            SelectByTag(RoutingBox, "full-tunnel");
            SelectByTag(PaddingBox, "0,255");
            SelectByTag(HeartbeatBox, "15000,2000");
            SniBox.Text = "www.microsoft.com";
            MtuBox.Text = "1500";
            DnsBox.Text = "1.1.1.1, 8.8.8.8";
            PortBox.Text = "443";
        }
        else
        {
            HeaderText.Text = Loc.T("EditProfileTitle");
            NameBox.Text = existing.Name ?? "";
            AddrBox.Text = existing.ServerAddress;
            PortBox.Text = existing.Port.ToString();
            SelectByTag(ModeBox, PresetIdOf(existing));
            SelectByTag(RoutingBox, existing.IsFullTunnel ? "full-tunnel" : "split-tunnel");
            SelectPadding(existing);
            SelectHeartbeat(existing);
            SniBox.Text = existing.Sni ?? "";
            ObfsKeyBox.Text = existing.ObfsKey;
            RealityIdBox.Text = existing.RealityShortId ?? "";
            UserBox.Text = existing.Username;
            PassBox.Password = existing.Password;
            KeyBox.Text = existing.ServerPublicKeyHex ?? "";
            MtuBox.Text = existing.Mtu > 0 ? existing.Mtu.ToString() : "auto";  // 0 = auto
            DnsBox.Text = string.Join(", ", existing.DnsServers);
            LocalBox.IsChecked = existing.RouteLocalNetworks;
        }

        UpdateConditionalFields();
    }

    public static VpnConfig? Show(Window owner, VpnConfig? existing)
    {
        var w = new ConfigEditorWindow(owner, existing);
        return w.ShowDialog() == true ? w._result : null;
    }

    private void OnModeChanged(object sender, SelectionChangedEventArgs e) => UpdateConditionalFields();

    private void UpdateConditionalFields()
    {
        if (ObfsKeyPanel == null) return; // during InitializeComponent
        var (_, mode, _, _) = PresetParams(TagOf(ModeBox));
        SetPanel(ObfsKeyPanel, mode == "obfs");       // obfs PSK
        SetPanel(RealityIdPanel, mode == "reality-tls"); // REALITY short_id (hex)
        // SNI only matters where a ClientHello reaches the wire: fake-tls (visible
        // mimicry) and reality-tls (cover domain). obfs masks it; plain has none.
        SetPanel(SniPanel, mode is "fake-tls" or "reality-tls");
    }

    private static void SetPanel(UIElement panel, bool on)
    {
        panel.IsEnabled = on;
        panel.Opacity = on ? 1.0 : 0.45;
        panel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>Map a preset id (the ModeBox tag) to (protocol, wire mode, obfs fronting, QUIC).</summary>
    private static (string proto, string mode, string front, bool quic) PresetParams(string? id) => id switch
    {
        "obfs-ws"     => ("tcp", "obfs", "websocket", false),
        "obfs-none"   => ("tcp", "obfs", "none", false),
        "udp"         => ("udp", "fake-tls", "websocket", false),
        "udp-quic"    => ("udp", "fake-tls", "websocket", true),
        "udp-obfs"    => ("udp", "obfs", "websocket", false),
        "reality-tls" => ("tcp", "reality-tls", "websocket", false),
        "plain"       => ("tcp", "plain", "websocket", false),   // no obfuscation, TCP only
        _             => ("tcp", "fake-tls", "websocket", false), // "faketls"
    };

    /// <summary>Pick the preset id that best represents an existing config (inverse of PresetParams).</summary>
    private static string PresetIdOf(VpnConfig c)
    {
        string mode = c.WireMode.ToLowerInvariant();
        bool udp = c.Protocol.Equals("udp", StringComparison.OrdinalIgnoreCase);
        if (mode == "reality-tls") return "reality-tls";
        if (mode == "plain") return "plain";
        if (udp)
        {
            if (mode == "obfs") return "udp-obfs";
            return c.QuicEnabled ? "udp-quic" : "udp";
        }
        if (mode == "obfs")
            return c.ObfsFronting.Equals("none", StringComparison.OrdinalIgnoreCase) ? "obfs-none" : "obfs-ws";
        return "faketls";
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;

    private void OnSave(object sender, RoutedEventArgs e)
    {
        if (AddrBox.Text.Trim().Length == 0) { Warn(Loc.T("NeedServer")); return; }
        if (!int.TryParse(PortBox.Text.Trim(), out int port) || port is < 1 or > 65535)
        { Warn(Loc.T("BadPort")); return; }
        if (UserBox.Text.Trim().Length == 0) { Warn(Loc.T("NeedLogin")); return; }

        _result = BuildFromForm();
        DialogResult = true;
    }

    /// <summary>Build a VpnConfig from the current form fields (no validation).</summary>
    private VpnConfig BuildFromForm()
    {
        var addr = AddrBox.Text.Trim();
        if (!int.TryParse(PortBox.Text.Trim(), out int port) || port is < 1 or > 65535) port = 443;
        // "auto"/blank/0/unparseable => 0 (auto: adopt server-pushed MTU).
        int mtu = int.TryParse(MtuBox.Text.Trim(), out int m) && m > 0 ? m : 0;
        var (proto, mode, front, quic) = PresetParams(TagOf(ModeBox));
        string routing = TagOf(RoutingBox) ?? "full-tunnel";
        string sni = SniBox.Text.Trim();
        string key = new string(KeyBox.Text.Trim().Where(Uri.IsHexDigit).ToArray());
        var dns = DnsBox.Text
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
        var (padEnabled, padMin, padMax) = ParsePadding(TagOf(PaddingBox));
        var (hbEnabled, hbInterval, hbJitter) = ParseHeartbeat(TagOf(HeartbeatBox));

        return new VpnConfig
        {
            Name = NameBox.Text.Trim().Length > 0 ? NameBox.Text.Trim() : (addr.Length > 0 ? addr : "profile"),
            ServerAddress = addr,
            Port = port,
            Protocol = proto,
            WireMode = mode,
            ObfsKey = mode == "obfs" ? ObfsKeyBox.Text.Trim() : "",
            ObfsFronting = front,
            RealityShortId = mode == "reality-tls" ? NormalizeHex(RealityIdBox.Text) : null,
            Sni = sni.Length > 0 ? sni : null,
            QuicEnabled = quic,
            Username = UserBox.Text.Trim(),
            Password = PassBox.Password,
            ServerPublicKeyHex = key.Length == 64 ? key.ToLowerInvariant() : null,
            RoutingMode = routing,
            AddDefaultGateway = routing == "full-tunnel",
            RouteLocalNetworks = LocalBox.IsChecked == true,
            Mtu = mtu,
            DnsServers = dns,
            PaddingEnabled = padEnabled,
            PaddingMin = padMin,
            PaddingMax = padMax,
            HeartbeatEnabled = hbEnabled,
            HeartbeatIntervalMs = hbInterval,
            HeartbeatJitterMs = hbJitter,
        };
    }

    // ── manual text editing of the config (INI / qeli:// / JSON) ──────────────────
    private void OnManualEdit(object sender, RoutedEventArgs e)
    {
        var text = BuildFromForm().ToIni();
        var edited = InputDialog.Show(this, Loc.T("ManualEdit"), Loc.T("ManualEditPrompt"), text, multiline: true);
        if (string.IsNullOrWhiteSpace(edited)) return;

        VpnConfig parsed;
        try
        {
            parsed = VpnConfig.Parse(edited.Trim());
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, Loc.F("ImportError", ex.Message), Loc.T("Profile"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Reflect the parsed config back into the form (INI-covered fields).
        NameBox.Text = parsed.Name ?? "";
        AddrBox.Text = parsed.ServerAddress;
        PortBox.Text = parsed.Port.ToString();
        SelectByTag(ModeBox, PresetIdOf(parsed));
        SniBox.Text = parsed.Sni ?? "";
        ObfsKeyBox.Text = parsed.ObfsKey;
        RealityIdBox.Text = parsed.RealityShortId ?? "";
        UserBox.Text = parsed.Username;
        PassBox.Password = parsed.Password;
        KeyBox.Text = parsed.ServerPublicKeyHex ?? "";
        LocalBox.IsChecked = parsed.RouteLocalNetworks;
        UpdateConditionalFields();
    }

    private void Warn(string msg) =>
        MessageBox.Show(this, msg, Loc.T("Profile"), MessageBoxButton.OK, MessageBoxImage.Warning);

    private static void SelectByTag(ComboBox box, string tag)
    {
        foreach (var obj in box.Items)
            if (obj is ComboBoxItem item && (item.Tag as string) == tag)
            { box.SelectedItem = item; return; }
        if (box.Items.Count > 0) box.SelectedIndex = 0;
    }

    private static string? TagOf(ComboBox box) => (box.SelectedItem as ComboBoxItem)?.Tag as string;

    /// <summary>Keep only hex digits, lower-cased; null when empty (REALITY short_id).</summary>
    private static string? NormalizeHex(string s)
    {
        var hex = new string(s.Trim().Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
        return hex.Length > 0 ? hex : null;
    }

    private void SelectPadding(VpnConfig c)
    {
        var tag = !c.PaddingEnabled ? "off" : $"{c.PaddingMin},{c.PaddingMax}";
        // Fall back to "Custom-equivalent" nearest preset if not an exact match.
        if (!HasTag(PaddingBox, tag)) tag = c.PaddingEnabled ? "0,255" : "off";
        SelectByTag(PaddingBox, tag);
    }

    private void SelectHeartbeat(VpnConfig c)
    {
        var tag = !c.HeartbeatEnabled ? "off" : $"{c.HeartbeatIntervalMs},{c.HeartbeatJitterMs}";
        if (!HasTag(HeartbeatBox, tag)) tag = c.HeartbeatEnabled ? "15000,2000" : "off";
        SelectByTag(HeartbeatBox, tag);
    }

    private static bool HasTag(ComboBox box, string tag) =>
        box.Items.OfType<ComboBoxItem>().Any(i => (i.Tag as string) == tag);

    private static (bool, int, int) ParsePadding(string? tag)
    {
        if (string.IsNullOrEmpty(tag) || tag == "off") return (false, 0, 0);
        var p = tag.Split(',');
        return (true, int.Parse(p[0]), int.Parse(p[1]));
    }

    private static (bool, long, long) ParseHeartbeat(string? tag)
    {
        if (string.IsNullOrEmpty(tag) || tag == "off") return (false, 15000, 2000);
        var p = tag.Split(',');
        return (true, long.Parse(p[0]), long.Parse(p[1]));
    }
}
