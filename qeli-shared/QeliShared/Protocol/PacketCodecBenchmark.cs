using System.Diagnostics;
using Qeli.Shared.Crypto;

namespace Qeli.Shared.Protocol;

/// <summary>
/// Stable release-mode benchmark for the retained managed PacketCodec implementation. The
/// production transport lives in Rust; this measurement remains useful for cross-language
/// regression tracking and for demonstrating the cost removed from desktop packet paths.
/// </summary>
public static class PacketCodecBenchmark
{
    private const int PayloadBytes = 1400;
    private const int WarmupIterations = 1_000;
    private const int DefaultIterations = 20_000;
    private const double CiMinMibPerSecond = 10.0;
    private const double CiMaxAllocatedBytesPerRoundtrip = 32 * 1024;

    public static int Run(string implementation, string[] arguments)
    {
        try
        {
            bool ci = false;
            int iterations = ReadIterationsFromEnvironment();
            foreach (string argument in arguments)
            {
                if (string.Equals(argument, "--ci", StringComparison.OrdinalIgnoreCase))
                    ci = true;
                else if (argument.StartsWith("--iterations=", StringComparison.OrdinalIgnoreCase)
                    && int.TryParse(argument.AsSpan("--iterations=".Length), out int parsed))
                    iterations = parsed;
                else
                    throw new ArgumentException($"unknown argument: {argument}");
            }
            if (iterations <= 0) throw new ArgumentOutOfRangeException(nameof(iterations));

            byte[] key = Enumerable.Repeat((byte)0x42, 32).ToArray();
            byte[] payload = Enumerable.Repeat((byte)0xA5, PayloadBytes).ToArray();
            var encryptor = new PacketCodec(new PacketCipher(key), paddingEnabled: false);
            var decryptor = new PacketCodec(new PacketCipher(key), paddingEnabled: false);
            RunRoundtrips(encryptor, decryptor, payload, WarmupIterations);

            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
            var stopwatch = Stopwatch.StartNew();
            long checksum = RunRoundtrips(encryptor, decryptor, payload, iterations);
            stopwatch.Stop();
            long allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;

            double mib = (double)iterations * PayloadBytes / (1024 * 1024);
            double mibPerSecond = mib / stopwatch.Elapsed.TotalSeconds;
            double allocatedPerRoundtrip = (double)allocated / iterations;
            Console.WriteLine(FormattableString.Invariant(
                $"{{\"implementation\":\"{implementation}\",\"payload_bytes\":{PayloadBytes},\"iterations\":{iterations},\"elapsed_ms\":{stopwatch.Elapsed.TotalMilliseconds:F3},\"mib_per_second\":{mibPerSecond:F3},\"allocated_bytes_per_roundtrip\":{allocatedPerRoundtrip:F1},\"checksum\":{checksum}}}"));

            if (ci && mibPerSecond < CiMinMibPerSecond)
                throw new InvalidOperationException(
                    $"throughput {mibPerSecond:F3} MiB/s is below the conservative CI floor " +
                    $"{CiMinMibPerSecond:F1} MiB/s");
            if (ci && allocatedPerRoundtrip > CiMaxAllocatedBytesPerRoundtrip)
                throw new InvalidOperationException(
                    $"allocation {allocatedPerRoundtrip:F1} B/roundtrip exceeds the CI ceiling " +
                    $"{CiMaxAllocatedBytesPerRoundtrip:F0} B/roundtrip");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine($"packet-codec-bench: {error.Message}");
            return 1;
        }
    }

    private static int ReadIterationsFromEnvironment()
    {
        string? value = Environment.GetEnvironmentVariable("QELI_PACKET_BENCH_ITERS");
        if (string.IsNullOrWhiteSpace(value)) return DefaultIterations;
        if (!int.TryParse(value, out int iterations) || iterations <= 0)
            throw new ArgumentException("QELI_PACKET_BENCH_ITERS must be a positive integer");
        return iterations;
    }

    private static long RunRoundtrips(PacketCodec encryptor, PacketCodec decryptor,
        byte[] payload, int iterations)
    {
        long checksum = 0;
        for (int iteration = 0; iteration < iterations; iteration++)
        {
            byte[] record = encryptor.Encrypt(payload);
            byte[] plaintext = decryptor.Decrypt(record);
            if (!plaintext.AsSpan().SequenceEqual(payload))
                throw new InvalidOperationException($"round-trip mismatch at iteration {iteration}");
            checksum += plaintext[iteration % plaintext.Length];
        }
        return checksum;
    }
}
