using System.Text.Json;
using Qeli.Shared.Model;

namespace Qeli.Conformance;

internal static class ConfigBoundaryConformance
{
    internal static void Run(Action<string, bool> check)
    {
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
        foreach (var item in root.GetProperty("cases").EnumerateArray())
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
    }
}
