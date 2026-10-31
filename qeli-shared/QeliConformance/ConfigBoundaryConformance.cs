using System.Text;
using System.Text.Json;
using Qeli.Shared.Model;

namespace Qeli.Conformance;

internal static class ConfigBoundaryConformance
{
    internal static void Run(Action<string, bool> check)
    {
        var permanent=VpnConfig.FromIni("[qeli]\nserver=vpn.example:443\nuser=test\npass=test\nwindows_persistent_adapter=true\n");
        check("persistent adapter: desktop archive preserves local opt-in",
            JsonSerializer.Deserialize<VpnConfig>(JsonSerializer.Serialize(permanent))!.WindowsPersistentAdapter);
        check("persistent adapter: local device installation policy is not exported in URI",
            !VpnConfig.FromQeliUri(permanent.ToQeliUri()).WindowsPersistentAdapter);
        foreach (var compact in new[] { "false", "true" })
        {
            var policy = new Dictionary<string, string> {
                ["reality_compact"] = compact, ["reality_split"] = "sni", ["reality_split_delay"] = "237"
            };
            var config = VpnConfig.FromIni("[qeli]\nserver=vpn.example:443\n" +
                string.Join("\n", policy.Select(p => $"{p.Key}={p.Value}")) + "\n");
            var edited = JsonSerializer.SerializeToNode(config)!;
            edited["Password"] = "edited";
            var restored = VpnConfig.FromIni(edited.Deserialize<VpnConfig>()!.ToIni());
            check("REALITY policy survives desktop editing " + compact,
                policy.All(p => restored.CarriedKeys.TryGetValue(p.Key, out var value) && value == p.Value));
        }
        foreach (bool pull in new[] { true, false })
        {
            var config = VpnConfig.FromIni("[qeli]\nserver=vpn.example:443\nuser=test\npass=test\npull_routes=" + pull.ToString().ToLowerInvariant() + "\n");
            var restored = JsonSerializer.Deserialize<VpnConfig>(JsonSerializer.Serialize(config))!;
            check("route policy: desktop archive preserves " + pull, restored.PullRoutes == pull);
            check("route policy: archived INI preserves " + pull, VpnConfig.FromIni(restored.ToIni()).PullRoutes == pull);
            check("route policy: shared URI preserves " + pull, VpnConfig.FromQeliUri(restored.ToQeliUri()).PullRoutes == pull);
        }

        string? path = null;
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "conformance", "config-boundary.json");
            if (File.Exists(candidate)) { path = candidate; break; }
        }
        check("config boundary corpus present", path != null);
        if (path == null) return;
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        var cases = root.GetProperty("cases");
        check("config boundary corpus is non-empty", cases.GetArrayLength() > 0);
        if (cases.GetArrayLength() == 0) return;
        foreach (var item in cases.EnumerateArray())
        {
            bool valid;
            try
            {
                VpnConfig.FromIni(root.GetProperty("base").GetString() + item.GetProperty("ini").GetString()).Validate();
                valid = true;
            }
            catch (ArgumentException) { valid = false; }
            catch (FormatException) { valid = false; }
            check("config boundary: " + item.GetProperty("name").GetString(),
                valid == item.GetProperty("valid").GetBoolean());
        }
        var configPath = Path.Combine(Path.GetTempPath(), $"qeli-config-input-{Guid.NewGuid():N}.conf");
        try
        {
            var validIni = root.GetProperty("base").GetString() + "server = vpn.example.com:443\n";
            File.WriteAllText(configPath, validIni, new UTF8Encoding(false, true));
            check("config file: valid UTF-8 INI loads", VpnConfig.ParseFile(configPath).ServerAddress == "vpn.example.com");

            File.WriteAllBytes(configPath, [.. Encoding.UTF8.GetBytes(validIni), 0xff]);
            bool invalidUtf8Rejected = false;
            try { _ = VpnConfig.ParseFile(configPath); }
            catch (DecoderFallbackException) { invalidUtf8Rejected = true; }
            check("config file: malformed UTF-8 is rejected", invalidUtf8Rejected);

            File.WriteAllBytes(configPath, new byte[256 * 1024 + 1]);
            bool oversizedRejected = false;
            try { _ = VpnConfig.ParseFile(configPath); }
            catch (ArgumentException) { oversizedRejected = true; }
            check("config file: over-budget input is rejected before parsing", oversizedRejected);
        }
        finally { File.Delete(configPath); }
    }
}
