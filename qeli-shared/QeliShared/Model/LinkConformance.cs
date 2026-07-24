using System.Text.Json;

namespace Qeli.Shared.Model;

/// <summary>
/// Cross-implementation conformance for the <c>qeli://</c> link, driven by the SAME
/// fixtures the Rust, Kotlin and Swift suites use (<c>conformance/qeli-links.json</c> at
/// the repository root).
///
/// The link format is implemented four separate times in four languages, so every field is
/// four chances to disagree — and the failure is silent: the link "imports fine" with a
/// field dropped or re-defaulted, and the user ends up with a profile that cannot connect.
/// Writing these fixtures immediately exposed one such split: Swift and C# rejected an
/// out-of-range port while Rust accepted 0 and Kotlin accepted anything at all.
///
/// Lives in the shared library so the Windows and macOS <c>selftest</c> verbs both run it
/// (CI executes that verb on both platforms).
/// </summary>
public static class LinkConformance
{
    /// <summary>
    /// Run every fixture, reporting each through <paramref name="check"/> (name, passed).
    ///
    /// Returns false only when the fixtures could not be run at all. A shipped app has no
    /// repository next to it, so a missing fixture file is a SKIP rather than a failure —
    /// except when <c>QELI_CONFORMANCE_REQUIRED=1</c>, which CI sets so that a fixture file
    /// that moved cannot turn the gate into a silent no-op.
    /// </summary>
    public static bool Run(Action<string, bool> check)
    {
        var path = FindFixtures();
        if (path == null)
        {
            bool required = Environment.GetEnvironmentVariable("QELI_CONFORMANCE_REQUIRED") == "1";
            check("qeli:// conformance fixtures found (conformance/qeli-links.json)", !required);
            if (!required)
                Console.WriteLine("  [SKIP] qeli:// conformance — fixtures not found (not running from a source tree)");
            return !required;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(File.ReadAllText(path));
        }
        catch (Exception e)
        {
            check($"qeli:// conformance fixtures parse ({e.Message})", false);
            return false;
        }

        using (doc)
        {
            var root = doc.RootElement;
            int cases = 0, rejects = 0;

            foreach (var c in root.GetProperty("cases").EnumerateArray())
            {
                cases++;
                string name = c.GetProperty("name").GetString() ?? "?";
                string uri = c.GetProperty("uri").GetString() ?? "";
                VpnConfig cfg;
                try
                {
                    cfg = VpnConfig.FromQeliUri(uri);
                }
                catch (Exception e)
                {
                    check($"conformance[{name}]: parses ({e.GetType().Name}: {e.Message})", false);
                    continue;
                }

                var e2 = c.GetProperty("expect");
                bool ok = true;
                ok &= Str(e2, "host", cfg.ServerAddress, name, check);
                if (e2.TryGetProperty("port", out var port))
                    ok &= Report($"conformance[{name}]: port", port.GetInt32() == cfg.Port, check);
                ok &= Str(e2, "user", cfg.Username, name, check);
                ok &= Str(e2, "pass", cfg.Password, name, check);
                ok &= Str(e2, "proto", cfg.Protocol, name, check);
                ok &= Str(e2, "mode", cfg.WireMode, name, check);
                // "" in the fixture means "unpinned"; C# models that as null.
                ok &= Str(e2, "server_key", cfg.ServerPublicKeyHex ?? "", name, check);
                ok &= Nullable(e2, "sni", cfg.Sni, name, check);
                ok &= Nullable(e2, "reality_sid", cfg.RealityShortId, name, check);
                // An absent obfs key is "" here, not null.
                ok &= Nullable(e2, "obfs_key", string.IsNullOrEmpty(cfg.ObfsKey) ? null : cfg.ObfsKey, name, check);
                if (e2.TryGetProperty("quic", out var quic))
                    ok &= Report($"conformance[{name}]: quic", quic.GetBoolean() == cfg.QuicEnabled, check);
                if (e2.TryGetProperty("awg", out var awg))
                    ok &= Report($"conformance[{name}]: awg", awg.GetBoolean() == cfg.AwgEnabled, check);
                if (e2.TryGetProperty("jc", out var jc))
                    ok &= Report($"conformance[{name}]: jc", jc.GetInt32() == cfg.AwgJc, check);
                if (e2.TryGetProperty("jmin", out var jmin))
                    ok &= Report($"conformance[{name}]: jmin", jmin.GetInt32() == cfg.AwgJmin, check);
                if (e2.TryGetProperty("jmax", out var jmax))
                    ok &= Report($"conformance[{name}]: jmax", jmax.GetInt32() == cfg.AwgJmax, check);

                // Round-trip: emit the link and re-import it. This is the check that catches
                // a field written into the link with nothing to read it back.
                if (ok)
                {
                    try
                    {
                        var again = VpnConfig.FromQeliUri(cfg.ToQeliUri());
                        bool rt = again.ServerAddress == cfg.ServerAddress
                                  && again.Port == cfg.Port
                                  && again.Username == cfg.Username
                                  && again.Password == cfg.Password
                                  && again.Protocol == cfg.Protocol
                                  && again.WireMode == cfg.WireMode
                                  && (again.ServerPublicKeyHex ?? "") == (cfg.ServerPublicKeyHex ?? "")
                                  && again.Sni == cfg.Sni
                                  && again.RealityShortId == cfg.RealityShortId
                                  && again.ObfsKey == cfg.ObfsKey
                                  && again.QuicEnabled == cfg.QuicEnabled
                                  && again.AwgEnabled == cfg.AwgEnabled;
                        check($"conformance[{name}]: round-trip", rt);
                    }
                    catch (Exception e)
                    {
                        check($"conformance[{name}]: round-trip ({e.Message})", false);
                    }
                }
            }

            foreach (var c in root.GetProperty("reject").EnumerateArray())
            {
                rejects++;
                string name = c.GetProperty("name").GetString() ?? "?";
                string uri = c.GetProperty("uri").GetString() ?? "";
                bool parsed;
                try { VpnConfig.FromQeliUri(uri); parsed = true; }
                catch { parsed = false; }
                check($"conformance[{name}]: rejected", !parsed);
            }

            // Guard against a fixture file that loaded but contained nothing — a green run
            // over zero cases is the failure mode this whole exercise exists to prevent.
            check($"conformance fixtures non-empty ({cases} cases, {rejects} rejects)",
                  cases > 0 && rejects > 0);
        }
        return true;
    }

    private static bool Report(string name, bool ok, Action<string, bool> check)
    {
        check(name, ok);
        return ok;
    }

    private static bool Str(JsonElement expect, string key, string actual, string caseName,
                            Action<string, bool> check)
    {
        if (!expect.TryGetProperty(key, out var v) || v.ValueKind != JsonValueKind.String) return true;
        return Report($"conformance[{caseName}]: {key}", v.GetString() == actual, check);
    }

    /// <summary>Fixture value that may be JSON null, meaning "absent".</summary>
    private static bool Nullable(JsonElement expect, string key, string? actual, string caseName,
                                 Action<string, bool> check)
    {
        if (!expect.TryGetProperty(key, out var v)) return true;
        string? want = v.ValueKind == JsonValueKind.Null ? null : v.GetString();
        // Treat null and "" as the same "absent" for this comparison: the platforms differ
        // in which of the two they use, and that difference is not a protocol divergence.
        bool same = string.IsNullOrEmpty(want) ? string.IsNullOrEmpty(actual) : want == actual;
        return Report($"conformance[{caseName}]: {key}", same, check);
    }

    /// <summary>
    /// Walk up from the working directory looking for <c>conformance/qeli-links.json</c>,
    /// rather than hardcoding a depth — the selftest runs from different directories on
    /// Windows and macOS, and a wrong fixed path would silently find nothing.
    /// </summary>
    private static string? FindFixtures()
    {
        var env = Environment.GetEnvironmentVariable("QELI_CONFORMANCE_FIXTURES");
        if (!string.IsNullOrEmpty(env) && File.Exists(env)) return env;

        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "conformance", "qeli-links.json");
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        return null;
    }
}
