using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Layout;
using QeliMac.Model;
using Qeli.Shared;
using Qeli.Shared.Model;

namespace QeliMac;

/// <summary>
/// Form-based profile editor: exposes only the fields a user can sensibly set, via
/// dropdowns/inputs, and builds a <see cref="VpnConfig"/> from them (the server pushes
/// the rest). One preset (<c>ModeBox</c>) drives transport + wire mode + fronting +
/// QUIC, mirroring qeli-win's ConfigEditorWindow. Use <see cref="ShowAsync"/>.
/// </summary>
public partial class ConfigEditorWindow : Window
{
    private VpnConfig? _result;
    // The profile being edited (or the last manually-parsed config). Fields with no form
    // control — OpenVPN local/lport/dev_node/metric/route_file/persist_tun, kill-switch,
    // AWG, reconnect, shaping, Id — are carried over from here on Save so the form rebuild
    // doesn't drop them (issue #69). Null for a brand-new profile.
    private VpnConfig? _base;

    public ConfigEditorWindow() => InitializeComponent();

    public ConfigEditorWindow(Window owner, VpnConfig? existing) : this()
    {
        Icon = owner.Icon;
        _base = existing;
        Opened += (_, _) => FitToWorkArea();

        SniBox.ItemsSource = new[] { "www.microsoft.com", "www.cloudflare.com", "www.apple.com", "www.google.com", "www.amazon.com" };
        MtuBox.ItemsSource = new[] { "0", "1500", "1400", "1280", "1200" };
        DnsBox.ItemsSource = new[] { "1.1.1.1, 8.8.8.8", "1.1.1.1, 1.0.0.1", "8.8.8.8, 8.8.4.4", "9.9.9.9, 149.112.112.112" };
        TimeoutBox.ItemsSource = new[] { "15", "30", "60", "120" };

        if (existing == null)
        {
            HeaderText.Text = Loc.T("NewProfileTitle");
            SelectByTag(ModeBox, "faketls");
            SelectByTag(RoutingBox, "full-tunnel");
            SelectByTag(AppsModeBox, "all");
            SelectByTag(DnsModeBox, "tunnel");
            SelectByTag(ReconnectRetriesBox, "-1");
            SelectByTag(PaddingBox, "0,255");
            SelectByTag(HeartbeatBox, "15000,2000");
            SniBox.Text = "www.microsoft.com";
            MtuBox.Text = "0";
            DnsBox.Text = "";
            PortBox.Text = "443";
            TimeoutBox.Text = "30";
            ReconnectBox.IsChecked = true;
            PersistTunBox.IsChecked = false;
            MtuProbeBox.IsChecked = true;
            KillSwitchBox.IsChecked = false;
        }
        else
        {
            HeaderText.Text = Loc.T("EditProfileTitle");
            NameBox.Text = existing.Name ?? "";
            AddrBox.Text = existing.ServerAddress;
            PortBox.Text = existing.Port.ToString();
            SelectByTag(ModeBox, PresetIdOf(existing));
            SelectByTag(RoutingBox, existing.IsFullTunnel ? "full-tunnel" : "split-tunnel");
            SelectByTag(AppsModeBox, NormalizeAppsMode(existing.AppsMode));
            SelectByTag(DnsModeBox, NormalizeDnsMode(existing.DnsMode));
            SelectRetryCount(existing.ReconnectMaxRetries);
            SelectPadding(existing);
            SelectHeartbeat(existing);
            SniBox.Text = existing.Sni ?? "";
            ObfsKeyBox.Text = existing.ObfsKey;
            RealityIdBox.Text = existing.RealityShortId ?? "";
            UserBox.Text = existing.Username;
            PassBox.Text = existing.Password;
            KeyBox.Text = existing.ServerPublicKeyHex ?? "";
            MtuBox.Text = existing.Mtu.ToString();  // 0 = auto
            DnsBox.Text = string.Join(", ", existing.DnsServers);
            LocalBox.IsChecked = existing.RouteLocalNetworks;
            TimeoutBox.Text = existing.ConnectionTimeoutSecs.ToString();
            ReconnectBox.IsChecked = existing.ReconnectEnabled;
            PersistTunBox.IsChecked = existing.PersistTun;
            MtuProbeBox.IsChecked = existing.MtuProbe;
            KillSwitchBox.IsChecked = existing.KillSwitch;
            AppsBox.Text = string.Join(", ", existing.Apps);
        }

        UpdateConditionalFields();
        UpdateAppsUi();
        UpdateReconnectUi();
        UpdateDnsUi();
        UpdateRoutingUi();
    }

    public static async Task<VpnConfig?> ShowAsync(Window owner, VpnConfig? existing)
    {
        var w = new ConfigEditorWindow(owner, existing);
        await w.ShowDialog(owner);
        return w._result;
    }

    private void OnModeChanged(object? sender, SelectionChangedEventArgs e) => UpdateConditionalFields();

    private void OnAppsModeChanged(object? sender, SelectionChangedEventArgs e) => UpdateAppsUi();

    private void OnReconnectChanged(object? sender, RoutedEventArgs e) => UpdateReconnectUi();

    private void OnDnsModeChanged(object? sender, SelectionChangedEventArgs e) => UpdateDnsUi();

    private void OnRoutingChanged(object? sender, SelectionChangedEventArgs e) => UpdateRoutingUi();

    private void UpdateReconnectUi()
    {
        if (ReconnectPanel == null) return;
        bool enabled = ReconnectBox.IsChecked == true;
        ReconnectPanel.IsEnabled = enabled;
        ReconnectPanel.Opacity = enabled ? 1.0 : 0.45;
    }

    private void UpdateDnsUi()
    {
        if (DnsServersPanel == null) return;
        bool enabled = TagOf(DnsModeBox) == "tunnel";
        DnsServersPanel.IsEnabled = enabled;
        DnsServersPanel.Opacity = enabled ? 1.0 : 0.45;
    }

    private void UpdateRoutingUi()
    {
        if (KillSwitchBox == null) return;
        bool enabled = TagOf(RoutingBox) == "full-tunnel";
        KillSwitchBox.IsEnabled = enabled;
        KillSwitchBox.Opacity = enabled ? 1.0 : 0.45;
    }

    private void UpdateAppsUi()
    {
        if (AppsBox == null) return;
        bool enabled = TagOf(AppsModeBox) is "include" or "exclude";
        AppsBox.IsEnabled = enabled;
        AppsPickBtn.IsEnabled = enabled;
        AppsHintText.IsVisible = enabled;
        AppsBox.Opacity = enabled ? 1.0 : 0.45;
        AppsPickBtn.Opacity = enabled ? 1.0 : 0.45;
    }

    private async void OnPickApps(object? sender, RoutedEventArgs e)
    {
        var picked = await MacAppPickerWindow.ShowAsync(this, ParsedApps());
        if (picked != null) AppsBox.Text = string.Join(", ", picked);
    }

    private static string NormalizeAppsMode(string mode) =>
        mode.Equals("include", StringComparison.OrdinalIgnoreCase) ? "include"
        : mode.Equals("exclude", StringComparison.OrdinalIgnoreCase) ? "exclude"
        : "all";

    private List<string> ParsedApps() => (AppsBox.Text ?? "")
        .Split(new[] { ',', ';', '\r', '\n', '\t', ' ' },
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Distinct(StringComparer.Ordinal)
        .ToList();

    private void UpdateConditionalFields()
    {
        if (ObfsKeyPanel == null) return; // during InitializeComponent
        var (_, mode, _, _) = PresetParams(TagOf(ModeBox));
        SetPanel(ObfsKeyPanel, mode == "obfs");           // obfs PSK
        SetPanel(RealityIdPanel, mode == "reality-tls");  // REALITY short_id (hex)
        // SNI only matters where a ClientHello reaches the wire: fake-tls (visible
        // mimicry) and reality-tls (cover domain). obfs masks it; plain has none.
        SetPanel(SniPanel, mode is "fake-tls" or "reality-tls");
    }

    private static void SetPanel(Control panel, bool on)
    {
        panel.IsEnabled = on;
        panel.Opacity = on ? 1.0 : 0.45;
        panel.IsVisible = on;
    }

    /// <summary>Map a preset id (the ModeBox tag) to (protocol, wire mode, obfs fronting, QUIC).</summary>
    private static (string proto, string mode, string front, bool quic) PresetParams(string? id) => id switch
    {
        "obfs-ws" => ("tcp", "obfs", "websocket", false),
        "obfs-none" => ("tcp", "obfs", "none", false),
        "udp" => ("udp", "fake-tls", "websocket", false),
        "udp-quic" => ("udp", "fake-tls", "websocket", true),
        "udp-obfs" => ("udp", "obfs", "websocket", false),
        "reality-tls" => ("tcp", "reality-tls", "websocket", false),
        "plain" => ("tcp", "plain", "websocket", false),    // no obfuscation, TCP only
        _ => ("tcp", "fake-tls", "websocket", false), // "faketls"
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

    private void OnCancel(object? sender, RoutedEventArgs e) => Close();

    private async void OnSave(object? sender, RoutedEventArgs e)
    {
        if ((AddrBox.Text ?? "").Trim().Length == 0) { await Warn(Loc.T("NeedServer")); return; }
        if (!int.TryParse((PortBox.Text ?? "").Trim(), out int port) || port is < 1 or > 65535)
        { await Warn(Loc.T("BadPort")); return; }
        if (!long.TryParse((TimeoutBox.Text ?? "").Trim(), out long timeout) || timeout is < 1 or > 300)
        { await Warn(Loc.T("BadTimeout")); return; }
        if (!TryParseMtu(MtuBox.Text ?? "", out _)) { await Warn(Loc.T("BadMtu")); return; }
        if ((UserBox.Text ?? "").Trim().Length == 0) { await Warn(Loc.T("NeedLogin")); return; }
        if ((TagOf(AppsModeBox) is "include" or "exclude") && ParsedApps().Count == 0)
        { await Warn(Loc.T("NeedApps")); return; }

        _result = BuildFromForm();
        Close();
    }

    /// <summary>Build a VpnConfig from the current form fields (no validation).</summary>
    private VpnConfig BuildFromForm()
    {
        var addr = (AddrBox.Text ?? "").Trim();
        if (!int.TryParse((PortBox.Text ?? "").Trim(), out int port) || port is < 1 or > 65535) port = 443;
        // 0/"auto"/blank/unparseable => 0 (auto: probe/adopt server-pushed MTU).
        int mtu = TryParseMtu(MtuBox.Text ?? "", out int parsedMtu) ? parsedMtu : 0;
        var (proto, mode, front, quic) = PresetParams(TagOf(ModeBox));
        string routing = TagOf(RoutingBox) ?? "full-tunnel";
        string sni = (SniBox.Text ?? "").Trim();
        string key = new string((KeyBox.Text ?? "").Trim().Where(Uri.IsHexDigit).ToArray());
        var dns = (DnsBox.Text ?? "")
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
        var (padEnabled, padMin, padMax) = ParsePadding(TagOf(PaddingBox));
        var (hbEnabled, hbInterval, hbJitter) = ParseHeartbeat(TagOf(HeartbeatBox));
        long timeout = long.TryParse((TimeoutBox.Text ?? "").Trim(), out var timeoutValue)
            ? Math.Clamp(timeoutValue, 1, 300) : 30;
        int reconnectRetries = int.TryParse(TagOf(ReconnectRetriesBox), out var retries)
            ? retries : -1;

        // Start from _base (the profile being edited / last manually-parsed config) so
        // every field with no form control survives the Save; override only what the form
        // owns. For a brand-new profile _base is null → defaults apply (issue #69).
        return (_base ?? new VpnConfig()).WithEditorFields(
            name: (NameBox.Text ?? "").Trim().Length > 0 ? NameBox.Text!.Trim() : (addr.Length > 0 ? addr : "profile"),
            serverAddress: addr,
            port: port,
            protocol: proto,
            wireMode: mode,
            obfsKey: mode == "obfs" ? (ObfsKeyBox.Text ?? "").Trim() : "",
            obfsFronting: front,
            realityShortId: mode == "reality-tls" ? NormalizeHex(RealityIdBox.Text ?? "") : null,
            sni: sni.Length > 0 ? sni : null,
            quicEnabled: quic,
            username: (UserBox.Text ?? "").Trim(),
            password: PassBox.Text ?? "",
            serverPublicKeyHex: key.Length == 64 ? key.ToLowerInvariant() : null,
            routingMode: routing,
            addDefaultGateway: routing == "full-tunnel",
            routeLocalNetworks: LocalBox.IsChecked == true,
            mtu: mtu,
            dnsServers: dns,
            paddingEnabled: padEnabled,
            paddingMin: padMin,
            paddingMax: padMax,
            heartbeatEnabled: hbEnabled,
            heartbeatIntervalMs: hbInterval,
            heartbeatJitterMs: hbJitter,
            appsMode: TagOf(AppsModeBox) ?? "all",
            apps: ParsedApps(),
            connectionTimeoutSecs: timeout,
            reconnectEnabled: ReconnectBox.IsChecked == true,
            reconnectMaxRetries: reconnectRetries,
            persistTun: PersistTunBox.IsChecked == true,
            mtuProbe: MtuProbeBox.IsChecked == true,
            killSwitch: KillSwitchBox.IsChecked == true,
            dnsMode: TagOf(DnsModeBox) ?? "tunnel");
    }

    // ── manual text editing of the config (INI / qeli://) ─────────────────────────
    private async void OnManualEdit(object? sender, RoutedEventArgs e)
    {
        var text = BuildFromForm().ToIni();
        var edited = await InputDialog.ShowAsync(this, Loc.T("ManualEdit"), Loc.T("ManualEditPrompt"), text, multiline: true);
        if (string.IsNullOrWhiteSpace(edited)) return;

        VpnConfig parsed;
        try { parsed = VpnConfig.Parse(edited.Trim()); }
        catch (Exception ex)
        {
            await Dialogs.InfoAsync(this, Loc.F("ImportError", ex.Message), Loc.T("Profile"));
            return;
        }

        // Carry the parsed config as the new base so its non-form fields (OpenVPN options,
        // AWG, reconnect, shaping, Id) survive the next Save (issue #69).
        _base = parsed;

        // Reflect the parsed config back into the form. Every form-owned field must be
        // reflected — BuildFromForm reads the form controls, so a field left stale here
        // would clobber the manual edit on Save (Mtu/Dns/Routing/Padding/Heartbeat).
        NameBox.Text = parsed.Name ?? "";
        AddrBox.Text = parsed.ServerAddress;
        PortBox.Text = parsed.Port.ToString();
        SelectByTag(ModeBox, PresetIdOf(parsed));
        SelectByTag(RoutingBox, parsed.IsFullTunnel ? "full-tunnel" : "split-tunnel");
        SelectByTag(DnsModeBox, NormalizeDnsMode(parsed.DnsMode));
        SelectRetryCount(parsed.ReconnectMaxRetries);
        SelectPadding(parsed);
        SelectHeartbeat(parsed);
        SniBox.Text = parsed.Sni ?? "";
        ObfsKeyBox.Text = parsed.ObfsKey;
        RealityIdBox.Text = parsed.RealityShortId ?? "";
        UserBox.Text = parsed.Username;
        PassBox.Text = parsed.Password;
        KeyBox.Text = parsed.ServerPublicKeyHex ?? "";
        MtuBox.Text = parsed.Mtu.ToString();  // 0 = auto
        DnsBox.Text = string.Join(", ", parsed.DnsServers);
        LocalBox.IsChecked = parsed.RouteLocalNetworks;
        TimeoutBox.Text = parsed.ConnectionTimeoutSecs.ToString();
        ReconnectBox.IsChecked = parsed.ReconnectEnabled;
        PersistTunBox.IsChecked = parsed.PersistTun;
        MtuProbeBox.IsChecked = parsed.MtuProbe;
        KillSwitchBox.IsChecked = parsed.KillSwitch;
        SelectByTag(AppsModeBox, NormalizeAppsMode(parsed.AppsMode));
        AppsBox.Text = string.Join(", ", parsed.Apps);
        UpdateConditionalFields();
        UpdateAppsUi();
        UpdateReconnectUi();
        UpdateDnsUi();
        UpdateRoutingUi();
    }

    private Task Warn(string msg) => Dialogs.InfoAsync(this, msg, Loc.T("Profile"));

    private static void SelectByTag(ComboBox box, string tag)
    {
        foreach (var obj in box.Items)
            if (obj is ComboBoxItem item && (item.Tag as string) == tag) { box.SelectedItem = item; return; }
        if (box.ItemCount > 0) box.SelectedIndex = 0;
    }

    private static string? TagOf(ComboBox box) => (box.SelectedItem as ComboBoxItem)?.Tag as string;

    private static string NormalizeDnsMode(string mode) => mode.ToLowerInvariant() switch
    {
        "off" => "off",
        "system" => "system",
        _ => "tunnel",
    };

    private void SelectRetryCount(int retries)
    {
        string tag = retries.ToString();
        if (!HasTag(ReconnectRetriesBox, tag))
            ReconnectRetriesBox.Items.Add(new ComboBoxItem
            {
                Content = Loc.F("RetriesCustom", retries),
                Tag = tag,
            });
        SelectByTag(ReconnectRetriesBox, tag);
    }

    private void FitToWorkArea()
    {
        var screen = Screens.ScreenFromWindow(this) ?? Screens.Primary ?? Screens.All.FirstOrDefault();
        if (screen == null) return;
        double available = Math.Max(MinHeight, screen.WorkingArea.Height / screen.Scaling - 32);
        MaxHeight = available;
        Height = Math.Min(Height, available);
    }

    /// <summary>Keep only hex digits, lower-cased; null when empty (REALITY short_id).</summary>
    private static string? NormalizeHex(string s)
    {
        var hex = new string(s.Trim().Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
        return hex.Length > 0 ? hex : null;
    }

    private static bool TryParseMtu(string text, out int mtu)
    {
        text = text.Trim();
        if (text.Length == 0 || text.Equals("auto", StringComparison.OrdinalIgnoreCase))
        { mtu = 0; return true; }
        return int.TryParse(text, out mtu) && (mtu == 0 || mtu is >= 576 and <= 16638);
    }

    private void SelectPadding(VpnConfig c)
    {
        var tag = !c.PaddingEnabled ? "off" : $"{c.PaddingMin},{c.PaddingMax}";
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
