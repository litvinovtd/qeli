using System.Text.Json;

namespace Qeli.Shared;

/// <summary>Result of a successful update check.</summary>
/// <param name="LatestVersion">Normalized latest release version, e.g. "0.7.6".</param>
/// <param name="ReleaseUrl">Human release page (release.html_url) to open in a browser.</param>
/// <param name="IsNewer">True if <see cref="LatestVersion"/> is strictly newer than the caller's current version.</param>
public sealed record UpdateInfo(string LatestVersion, string ReleaseUrl, bool IsNewer);

/// <summary>
/// Opt-in "check for updates" for the C# GUI clients (qeli-win, qeli-mac).
///
/// PRIVACY (this is a censorship-resistance VPN — see the published Privacy policy §2.1/§2.2
/// and THREAT-MODEL): the check is NEVER run unless the caller explicitly enables it and only
/// while the tunnel is UP (so the request and the real client IP travel INSIDE the tunnel).
/// The request is a bare, unauthenticated GET of PUBLIC release metadata with a GENERIC
/// User-Agent — it sends NO version, device id, OS or any identifying parameter; version
/// comparison happens locally. It is notification-only: it returns the latest version and the
/// release page URL; it NEVER downloads or installs anything.
///
/// Endpoint is the releases LIST (not /releases/latest, which silently skips pre-releases —
/// and every qeli release so far is a pre-release), mirroring install-reality-server.sh.
/// Any error / timeout / rate-limit (GitHub allows 60 req/h/IP unauthenticated) fails soft to
/// null so the UI simply shows nothing.
/// </summary>
public static class UpdateChecker
{
    // Public release metadata for the project. No token, no auth.
    private const string ReleasesUrl = "https://api.github.com/repos/litvinovtd/qeli/releases";
    private const string ReleasesPage = "https://github.com/litvinovtd/qeli/releases";

    // GitHub 403s a request with no User-Agent, but a qeli-branded UA hitting api.github.com
    // is itself a "this host runs qeli" fingerprint — so send a generic, non-identifying value.
    private const string GenericUserAgent = "Mozilla/5.0";

    private static readonly System.TimeSpan Timeout = System.TimeSpan.FromSeconds(10);

    /// <summary>Fetch the newest non-draft release and compare it to <paramref name="currentVersion"/>.
    /// Returns null on any failure (fail-soft) — the caller treats null as "no update info".
    /// The caller is responsible for the opt-in gate and for only calling this while connected.</summary>
    public static async Task<UpdateInfo?> CheckAsync(string currentVersion, CancellationToken ct = default)
    {
        try
        {
            // UseProxy=false: deterministic behaviour regardless of any configured system proxy,
            // so the request follows the OS route table (i.e. the tunnel) and nothing else.
            using var handler = new HttpClientHandler { UseProxy = false, AllowAutoRedirect = true };
            using var http = new HttpClient(handler) { Timeout = Timeout };

            using var req = new HttpRequestMessage(HttpMethod.Get, ReleasesUrl);
            req.Headers.TryAddWithoutValidation("User-Agent", GenericUserAgent);
            req.Headers.TryAddWithoutValidation("Accept", "application/vnd.github+json");
            req.Headers.TryAddWithoutValidation("X-GitHub-Api-Version", "2022-11-28");

            using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return null; // incl. 403 rate-limit — fail soft

            await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);

            var latest = SelectLatest(doc.RootElement);
            if (latest is null) return null;

            var (tag, url) = latest.Value;
            var latestVer = SemVer.Normalize(tag);
            bool newer = SemVer.IsNewer(latestVer, currentVersion);
            return new UpdateInfo(latestVer, string.IsNullOrEmpty(url) ? ReleasesPage : url!, newer);
        }
        catch
        {
            return null; // network/parse/timeout — no update info, no user-visible error
        }
    }

    /// <summary>Pure pick logic (pre-releases INCLUDED): the first array element that is not a
    /// draft, returning (tag_name, html_url). Mirrors install-reality-server.sh's
    /// "map(select(.draft|not)) | .[0]". Returns null if the array is empty / malformed.</summary>
    private static (string tag, string? url)? SelectLatest(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Array) return null;
        foreach (var rel in root.EnumerateArray())
        {
            if (rel.ValueKind != JsonValueKind.Object) continue;
            if (rel.TryGetProperty("draft", out var d) && d.ValueKind == JsonValueKind.True) continue;
            var tag = rel.TryGetProperty("tag_name", out var t) ? t.GetString() : null;
            if (string.IsNullOrEmpty(tag)) continue;
            var url = rel.TryGetProperty("html_url", out var h) ? h.GetString() : null;
            return (tag!, url);
        }
        return null;
    }
}
