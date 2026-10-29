using System.Security;

namespace Qeli.Shared.Model;

/// <summary>Local trust scope, independent of wire framing and network-plan addresses.</summary>
public static class ServerIdentityPolicy
{
    public static bool IsKeyMismatch(string message) => message.Contains("SERVER KEY MISMATCH", StringComparison.Ordinal);

    public static string EndpointId(string protocol, string host, int port)
    {
        string transport = protocol.ToLowerInvariant();
        if (transport is not ("tcp" or "udp")) throw new SecurityException("Invalid server transport");
        host = host.Trim();
        if (host.Contains(':') && !host.StartsWith('[')) host = $"[{host}]";
        return $"{transport}://{host}:{port}";
    }

    public static string StorageId(string eventId, string protocol, string host, int port)
    {
        string scoped = EndpointId(protocol, host, port);
        if (eventId != scoped && eventId != $"{host}:{port}" && eventId != LegacyId(scoped))
            throw new SecurityException("Native server identity endpoint does not match the profile");
        return scoped;
    }

    public static string? LegacyId(string serverId)
    {
        if (!serverId.StartsWith("tcp://", StringComparison.Ordinal)
            && !serverId.StartsWith("udp://", StringComparison.Ordinal)) return null;
        string endpoint = serverId[6..];
        return endpoint.StartsWith('[') ? endpoint[1..].Replace("]:", ":") : endpoint;
    }

    /// <returns>True for an existing qualified pin, false for first use / matching legacy.</returns>
    public static bool CheckKnownHosts(string content, string serverId, string received)
    {
        bool Check(string id)
        {
            bool found = false;
            foreach (var line in content.Split('\n').Select(row => row.Trim()))
            {
                if (line.Length == 0 || line.StartsWith('#')) continue;
                var parts = line.Split((char[]?)null, 2, StringSplitOptions.RemoveEmptyEntries);
                if (parts[0] != id) continue;
                string pinned = parts.Length == 2 ? parts[1].Trim() : "<missing>";
                if (parts.Length != 2 || !string.Equals(pinned, received, StringComparison.OrdinalIgnoreCase))
                    throw new SecurityException($"SERVER KEY MISMATCH for {id} - possible MITM. Pinned {pinned}, got {received}. Verify the correct profile key before replacing any saved pin.");
                found = true;
            }
            return found;
        }
        if (Check(serverId)) return true;
        if (LegacyId(serverId) is string legacy) _ = Check(legacy);
        return false; // Matching legacy is copied by the caller's normal persistence path.
    }
}
