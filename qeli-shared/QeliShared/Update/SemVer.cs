namespace Qeli.Shared;

/// <summary>Minimal semantic-version parse + compare used by the update check.
/// We compare NUMERICALLY, never as strings (else "0.7.10" would sort before
/// "0.7.9"). A version reference may be a git tag ("v0.7.5"), an assembly version
/// ("0.7.5.0") or carry a pre-release / build suffix ("0.8.0-rc1+ci"); <see
/// cref="Normalize"/> reduces any of these to a bare dotted-numeric core.</summary>
public static class SemVer
{
    /// <summary>Strip a leading 'v', drop any '-prerelease' / '+build' suffix, and
    /// return the dotted-numeric core (e.g. "v0.8.0-rc1" → "0.8.0"). Never throws;
    /// junk collapses to "0".</summary>
    public static string Normalize(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "0";
        s = s.Trim();
        if (s.Length > 0 && (s[0] == 'v' || s[0] == 'V')) s = s.Substring(1);
        int cut = s.IndexOfAny(new[] { '-', '+' });
        if (cut >= 0) s = s.Substring(0, cut);
        return s.Length == 0 ? "0" : s;
    }

    /// <summary>Compare two version references part-by-part as integers after
    /// <see cref="Normalize"/>. Missing trailing parts count as 0, so "0.7" == "0.7.0".
    /// Returns &gt;0 if <paramref name="a"/> is newer, &lt;0 if older, 0 if equal.</summary>
    public static int Compare(string? a, string? b)
    {
        var pa = Normalize(a).Split('.');
        var pb = Normalize(b).Split('.');
        int n = System.Math.Max(pa.Length, pb.Length);
        for (int i = 0; i < n; i++)
        {
            int x = i < pa.Length && int.TryParse(pa[i], out var xi) ? xi : 0;
            int y = i < pb.Length && int.TryParse(pb[i], out var yi) ? yi : 0;
            if (x != y) return x < y ? -1 : 1;
        }
        return 0;
    }

    /// <summary>True if <paramref name="latest"/> is strictly newer than
    /// <paramref name="current"/>.</summary>
    public static bool IsNewer(string? latest, string? current) => Compare(latest, current) > 0;
}
