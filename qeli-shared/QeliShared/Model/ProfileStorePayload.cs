using System.Text.Json;

namespace Qeli.Shared.Model;

/// <summary>Structural validation and stable identity migration of encrypted desktop profiles.</summary>
public static class ProfileStorePayload
{
    public static List<VpnConfig> Decode(string json, JsonSerializerOptions? options = null)
        => Decode(json, out _, options);

    public static List<VpnConfig> Decode(
        string json,
        out bool needsIdMigration,
        JsonSerializerOptions? options = null)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Array)
            throw new JsonException("Profile store must contain an array.");

        needsIdMigration = false;
        var explicitIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var entry in root.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object)
                throw new JsonException("Profile store contains a non-object profile.");
            if (!entry.TryGetProperty("Id", out var id))
            {
                needsIdMigration = true;
                continue;
            }
            if (id.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(id.GetString())
                || !explicitIds.Add(id.GetString()!))
                throw new JsonException("Profile store contains an invalid or duplicate profile Id.");
        }

        var profiles = root.Deserialize<List<VpnConfig>>(options)
            ?? throw new JsonException("Profile store must contain an array.");
        ValidateProfiles(profiles);
        return profiles;
    }

    public static string Encode(IEnumerable<VpnConfig> profiles, JsonSerializerOptions? options = null)
    {
        var entries = profiles.ToList();
        ValidateProfiles(entries);
        return JsonSerializer.Serialize(entries, options);
    }

    private static void ValidateProfiles(IEnumerable<VpnConfig> profiles)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var profile in profiles)
        {
            if (profile is null || string.IsNullOrWhiteSpace(profile.Id)
                || !ids.Add(profile.Id))
                throw new JsonException("Profile store contains an invalid or duplicate profile.");
            Validate(profile);
        }
    }

    /// <summary>Reject explicit nulls before a persisted profile reaches UI/native code.</summary>
    public static void Validate(VpnConfig profile)
    {
        if (profile is null || string.IsNullOrWhiteSpace(profile.Id))
            throw new JsonException("Profile contains an invalid Id.");
        // System.Text.Json accepts explicit null even for non-nullable C# properties.
        // Those values would reach UI getters or native serialization after load.
        if (profile.ServerAddress is null || profile.Protocol is null
            || profile.Username is null || profile.Password is null
            || profile.LoggingLevel is null || profile.RoutingMode is null
            || profile.Ipv6Policy is null || profile.RoamingPolicy is null
            || profile.AppsMode is null || profile.DnsMode is null
            || profile.WireMode is null || profile.ObfsKey is null
            || profile.ObfsFronting is null
            || InvalidItems(profile.IncludeRoutes) || InvalidItems(profile.ExcludeRoutes)
            || InvalidItems(profile.AdditionalRouteFiles) || InvalidItems(profile.Apps)
            || InvalidItems(profile.DnsServers)
            || InvalidItems(profile.UnparsedBooleanKeys)
            || InvalidItems(profile.DuplicateKeys)
            || InvalidItems(profile.UnknownKeys)
            || InvalidItems(profile.UnparsedNumericKeys)
            || profile.CarriedKeys is null || profile.CarriedKeys.Values.Any(value => value is null)
            || profile.InvalidRawValues is null
            || profile.InvalidRawValues.Values.Any(value => value is null))
            throw new JsonException("Profile store contains a null required config field.");
    }

    private static bool InvalidItems(IEnumerable<string>? values)
        => values is null || values.Any(value => value is null);
}
