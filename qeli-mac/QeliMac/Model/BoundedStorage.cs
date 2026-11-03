namespace QeliMac.Model;

internal static class BoundedStorage
{
    // Read at most limit + one overflow sentinel even for growing/non-seekable input.
    internal static byte[] Read(Stream input, int limit)
    {
        if (limit < 0) throw new ArgumentOutOfRangeException(nameof(limit));
        if (input.CanSeek && (input.Length < 0 || input.Length > limit))
            throw new IOException($"Stored data exceeds its {limit}-byte limit");
        using var output = new MemoryStream(Math.Min(limit, 64 * 1024));
        var buffer = new byte[Math.Min(limit + 1L, 64 * 1024)];
        while (true)
        {
            int wanted = (int)Math.Min(buffer.Length, (long)limit - output.Length + 1);
            int read = input.Read(buffer, 0, wanted);
            if (read == 0) return output.ToArray();
            if (output.Length + read > limit)
                throw new IOException($"Stored data exceeds its {limit}-byte limit");
            output.Write(buffer, 0, read);
        }
    }
}
