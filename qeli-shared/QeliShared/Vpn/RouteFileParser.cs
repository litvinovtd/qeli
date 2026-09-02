using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace Qeli.Shared.Vpn;

/// <summary>Parser for desktop split-route files. It accepts both qeli's one-CIDR-per-line
/// form and the common OpenVPN exports (<c>route network netmask [gateway] [metric]</c>).</summary>
internal static class RouteFileParser
{
    private const int MaxRoutes = 250_000;

    internal static IReadOnlyList<string> Load(
        IEnumerable<string> paths, CancellationToken cancellationToken, Action<string> log)
    {
        var routes = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int files = 0;
        foreach (string rawPath in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string path = rawPath.Trim();
            if (path.Length == 0) continue;
            files++;
            try
            {
                foreach (string route in ParseLines(
                    File.ReadLines(path), path, cancellationToken))
                {
                    if (!seen.Add(route)) continue;
                    routes.Add(route);
                    if (routes.Count > MaxRoutes)
                        throw new InvalidDataException(
                            $"route_file set exceeds the {MaxRoutes} route safety limit");
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (InvalidDataException) { throw; }
            catch (Exception e)
            {
                throw new InvalidDataException(
                    $"cannot read route_file '{path}': {e.Message}", e);
            }
        }
        if (files > 0)
            log($"Loaded {routes.Count} unique route(s) from {files} route_file source(s)");
        return routes;
    }

    internal static IReadOnlyList<string> ParseLines(
        IEnumerable<string> lines, string source = "route_file",
        CancellationToken cancellationToken = default)
    {
        var routes = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int lineNumber = 0;
        foreach (string raw in lines)
        {
            cancellationToken.ThrowIfCancellationRequested();
            lineNumber++;
            string line = StripComment(raw).Trim();
            if (line.Length == 0) continue;
            string[] fields = line.Split((char[]?)null,
                StringSplitOptions.RemoveEmptyEntries);
            string candidate;
            if (fields[0].Equals("route", StringComparison.OrdinalIgnoreCase))
            {
                if (fields.Length < 2)
                    throw BadLine(source, lineNumber, "route has no network");
                if (fields[1].Contains('/'))
                {
                    candidate = fields[1];
                }
                else if (fields.Length >= 3)
                {
                    if (!TryPrefixFromMask(fields[2], out int prefix))
                    {
                        throw BadLine(source, lineNumber,
                            $"invalid IPv4 netmask '{fields[2]}'");
                    }
                    candidate = $"{fields[1]}/{prefix}";
                }
                else if (IPAddress.TryParse(fields[1], out var host)
                         && host.AddressFamily == AddressFamily.InterNetwork)
                {
                    candidate = $"{host}/32";
                }
                else
                {
                    throw BadLine(source, lineNumber,
                        "expected 'route <IPv4> <netmask>' or 'route <CIDR>'");
                }
            }
            else if (fields[0].Equals("route-ipv6", StringComparison.OrdinalIgnoreCase))
            {
                if (fields.Length < 2)
                    throw BadLine(source, lineNumber, "route-ipv6 has no CIDR");
                candidate = fields[1];
            }
            else
            {
                candidate = fields[0];
            }

            if (!TryNormalizeCidr(candidate, out string canonical))
                throw BadLine(source, lineNumber, $"invalid route '{candidate}'");
            if (seen.Add(canonical)) routes.Add(canonical);
        }
        return routes;
    }

    private static string StripComment(string line)
    {
        int hash = line.IndexOf('#');
        int semicolon = line.IndexOf(';');
        int cut = hash < 0 ? semicolon : semicolon < 0 ? hash : Math.Min(hash, semicolon);
        return cut < 0 ? line : line[..cut];
    }

    private static bool TryPrefixFromMask(string value, out int prefix)
    {
        prefix = 0;
        if (!IPAddress.TryParse(value, out var mask)
            || mask.AddressFamily != AddressFamily.InterNetwork)
            return false;
        bool zeroSeen = false;
        foreach (byte octet in mask.GetAddressBytes())
        {
            for (int bit = 7; bit >= 0; bit--)
            {
                bool one = (octet & (1 << bit)) != 0;
                if (one && zeroSeen) return false;
                if (one) prefix++; else zeroSeen = true;
            }
        }
        return true;
    }

    private static bool TryNormalizeCidr(string value, out string canonical)
    {
        canonical = "";
        int slash = value.LastIndexOf('/');
        if (slash <= 0 || slash == value.Length - 1
            || !IPAddress.TryParse(value[..slash], out var address)
            || !int.TryParse(value[(slash + 1)..], NumberStyles.None,
                CultureInfo.InvariantCulture, out int prefix))
            return false;
        byte[] bytes = address.GetAddressBytes();
        int maxPrefix = bytes.Length * 8;
        if (prefix < 0 || prefix > maxPrefix) return false;
        int whole = prefix / 8;
        int remainder = prefix % 8;
        if (remainder != 0)
        {
            bytes[whole] &= (byte)(0xff << (8 - remainder));
            whole++;
        }
        Array.Clear(bytes, whole, bytes.Length - whole);
        canonical = $"{new IPAddress(bytes)}/{prefix}";
        return true;
    }

    private static InvalidDataException BadLine(string source, int line, string detail) =>
        new($"{source}:{line}: {detail}");
}
