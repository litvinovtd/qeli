using System.Text;
using Qeli.Shared.Model;

namespace Qeli.Conformance;

internal static class AppSettingsStoreConformance
{
    private sealed class Settings
    {
        public string Theme { get; set; } = "system";
    }

    public static void Run(Action<string, bool> check)
    {
        var dir = Path.Combine(Path.GetTempPath(), "qeli-settings-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "settings.json");
            check("settings store: absent file uses defaults",
                AppSettingsStore.Load<Settings>(path).Theme == "system");

            AppSettingsStore.Save(new Settings { Theme = "light" }, path);
            AppSettingsStore.Save(new Settings { Theme = "dark" }, path);
            check("settings store: atomic update retains a readable backup",
                AppSettingsStore.Load<Settings>(path).Theme == "dark"
                && File.ReadAllText(path + ".bak").Contains("light", StringComparison.Ordinal));

            File.WriteAllBytes(path, [0xff]);
            var recovered = AppSettingsStore.Load<Settings>(path);
            var quarantined = Directory.GetFiles(dir, "settings.json.corrupt-*");
            check("settings store: invalid UTF-8 is preserved before backup recovery",
                recovered.Theme == "light" && !File.Exists(path)
                && quarantined.Length == 1
                && File.ReadAllBytes(quarantined[0]).SequenceEqual(new byte[] { 0xff }));

            AppSettingsStore.Save(new Settings { Theme = "new" }, path);
            var original = File.ReadAllBytes(path);
            bool oversizedWriteRejected = false;
            try
            {
                AppSettingsStore.Save(
                    new Settings { Theme = new string('x', AppSettingsStore.MaximumBytes + 1) },
                    path);
            }
            catch (IOException) { oversizedWriteRejected = true; }
            check("settings store: oversized save preserves the current file",
                oversizedWriteRejected && File.ReadAllBytes(path).SequenceEqual(original));

            File.WriteAllText(path, """{"Theme":"unicode"}""", Encoding.Unicode);
            check("settings store: legacy UTF-16 BOM remains readable",
                AppSettingsStore.Load<Settings>(path).Theme == "unicode");

            using (var large = File.Create(path))
                large.SetLength(AppSettingsStore.MaximumBytes + 1L);
            var fallback = AppSettingsStore.Load<Settings>(path);
            check("settings store: oversized input is quarantined before fallback",
                fallback.Theme == "light" && !File.Exists(path)
                && Directory.GetFiles(dir, "settings.json.corrupt-*").Length == 2);

            if (OperatingSystem.IsWindows())
            {
                File.WriteAllText(path, "broken");
                using (var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    bool refused = false;
                    try { AppSettingsStore.Load<Settings>(path); }
                    catch (IOException) { refused = true; }
                    check("settings store: failed quarantine cannot expose writable defaults",
                        refused && File.Exists(path));
                }
            }
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
