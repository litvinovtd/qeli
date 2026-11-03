using System.Text;

namespace Qeli.Shared.Vpn;

/// <summary>Parser for desktop split-route files. It accepts both qeli's one-CIDR-per-line
/// form and common OpenVPN inclusion exports (<c>route network netmask [gateway] [metric]</c>).
/// The shared core rejects <c>net_gateway</c> bypasses; use explicit INI exclusions.</summary>
internal static class RouteFileParser
{
    private const int MaxRoutes = 250_000;
    internal const int MaximumLineCharacters = 64 * 1024;
    private const int MaximumBatchCharacters = 128 * 1024;

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
                    ReadFileLines(path, cancellationToken), path, cancellationToken))
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

    private static IEnumerable<string> ReadFileLines(string path, CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(path);
        foreach (string line in ReadBoundedLines(reader, cancellationToken, path)) yield return line;
    }

    internal static IEnumerable<string> ReadBoundedLines(TextReader reader,
        CancellationToken cancellationToken, string source = "route_file")
    {
        var buffer = new char[4096];
        var line = new StringBuilder();
        bool afterCarriageReturn = false;
        long lineNumber = 1;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int count = reader.Read(buffer, 0, buffer.Length);
            if (count == 0) break;
            for (int i = 0; i < count; i++)
            {
                char ch = buffer[i];
                if (afterCarriageReturn && ch == '\n')
                {
                    afterCarriageReturn = false;
                    continue;
                }
                afterCarriageReturn = ch == '\r';
                if (ch is '\r' or '\n')
                {
                    yield return line.ToString();
                    line.Clear();
                    lineNumber++;
                    continue;
                }
                if (line.Length == MaximumLineCharacters)
                    throw new InvalidDataException($"{source}:{lineNumber}: route_file line exceeds 65536 characters");
                line.Append(ch);
            }
        }
        if (line.Length != 0) yield return line.ToString();
    }

    internal static IReadOnlyList<string> ParseLines(
        IEnumerable<string> lines, string source = "route_file",
        CancellationToken cancellationToken = default)
    {
        var routes = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var batch = new List<string>(512);
        long offset = 0;
        int batchCharacters = 0;
        void Flush()
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var result = Qeli.Shared.Model.ConfigCore.Policy("route_file", new { lines = batch, source, offset });
                foreach (var value in result.GetProperty("value").EnumerateArray())
                    if (seen.Add(value.GetString()!)) routes.Add(value.GetString()!);
            }
            catch (ArgumentException e) { throw new InvalidDataException(e.Message, e); }
            if (routes.Count > MaxRoutes) throw new InvalidDataException($"route_file set exceeds the {MaxRoutes} route safety limit");
            offset += batch.Count;
            batch.Clear();
            batchCharacters = 0;
        }
        foreach (var line in lines)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (line.Length > MaximumLineCharacters)
                throw new InvalidDataException($"{source}:{offset + batch.Count + 1}: route_file line exceeds 65536 characters");
            // JSON can expand a character to six bytes. Bound input batches by text
            // as well as line count before the native service request is serialized.
            if (batch.Count > 0 && batchCharacters + line.Length > MaximumBatchCharacters) Flush();
            batch.Add(line);
            batchCharacters += line.Length;
            if (batch.Count == 512) Flush();
        }
        if (batch.Count > 0) Flush();
        return routes;
    }
}
